# -*- coding: utf-8 -*-

"""Main module."""

import fnmatch
import functools
import hashlib
import os.path
import re
import sys
from zipfile import ZipFile, ZIP_DEFLATED
from base64 import b64encode


directory_re = re.compile(r"[\\/]$")
ZIPFILE_WRITE_EXCLUSIVE_MODE = 'x'
ZIPFILE_WRITE_MODE = 'w'
if sys.version_info >= (3, 5):
    ZIPFILE_WRITE_MODE = ZIPFILE_WRITE_EXCLUSIVE_MODE


def ignore_certain_metainf_files(filename):
    """
    We do not support multiple signatures in XPI signing because the client
    side code makes some pretty reasonable assumptions about a single signature
    on any given JAR.  This function returns True if the file name given is one
    that we dispose of to prevent multiple signatures.
    """
    ignore = ("META-INF/manifest.mf",
              "META-INF/*.sf",
              "META-INF/*.rsa",
              "META-INF/*.dsa",
              "META-INF/ids.json")

    for glob in ignore:
        # Explicitly match against all upper case to prevent the kind of
        # runtime errors that lead to https://bugzil.la/1169574
        if fnmatch.fnmatchcase(filename.upper(), glob.upper()):
            return True
    return False


def file_key(filename):
    '''Sort keys for xpi files

    The filenames in a manifest are ordered so that files not in a
    directory come before files in any directory, ordered
    alphabetically but ignoring case, with a few exceptions
    (install.rdf, chrome.manifest, icon.png and icon64.png come at the
    beginning; licenses come at the end).

    This order does not appear to affect anything in any way, but it
    looks nicer.
    '''
    prio = 4
    if filename == 'install.rdf':
        prio = 1
    elif filename in ["chrome.manifest", "icon.png", "icon64.png"]:
        prio = 2
    elif filename in ["MPL", "GPL", "LGPL", "COPYING", "LICENSE", "license.txt"]:
        prio = 5
    return (prio, os.path.split(filename.lower()))


def _digest(data):
    md5 = hashlib.md5()
    md5.update(data)
    sha1 = hashlib.sha1()
    sha1.update(data)
    return {'md5': md5.digest(), 'sha1': sha1.digest()}


class Section(object):
    __slots__ = ('name', 'digests')

    def __init__(self, name, digests={}):
        self.name = name
        self.digests = digests

    def __str__(self):
        # Important thing to note: placement of newlines in these strings is
        # sensitive and should not be changed without reading through
        # http://docs.oracle.com/javase/7/docs/technotes/guides/jar/jar.html#JAR%20Manifest
        # thoroughly.
        entry = ''
        # The spec for zip files only supports extended ASCII and UTF-8
        # See http://www.pkware.com/documents/casestudies/APPNOTE.TXT
        # and search for "language encoding" for details
        #
        # See https://bugzilla.mozilla.org/show_bug.cgi?id=1013347
        name = 'Name: {}'.format(self.name)

        # See https://bugzilla.mozilla.org/show_bug.cgi?id=841569#c35
        while name:
            entry += name[:72]
            name = name[72:]
            if name:
                entry += '\n '
        entry += '\n'
        order = list(self.digests.keys())
        order.sort()
        entry += 'Digest-Algorithms: {}\n'.format(' '.join([algo.upper() for algo in order]))
        for algo in order:
            entry += '{}-Digest: {}\n'.format(
                algo.upper(), b64encode(self.digests[algo]).decode('utf-8'))
        return entry


def manifest_header(type_name, version='1.0'):
    """Returns a header, suitable for use in a manifest.

    >>> manifest_header("signature")
    "Signature-Version: 1.0"

    :param type_name: The kind of manifest which needs a header: "manifest", "signature".
    :param version: The manifest version to encode in the header (default: '1.0')
    """
    return "{}-Version: {}".format(
        type_name.title(),
        version,
    )


class Manifest(object):
    # Older versions of Firefox crash if a JAR manifest style file doesn't
    # end in a blank line("\n\n").  For more details see:
    # https://bugzilla.mozilla.org/show_bug.cgi?id=1158467

    def __init__(self, sections, **kwargs):
        super(Manifest, self).__init__()
        self.sections = sections
        for k, v in kwargs.items():
            setattr(self, k, v)

    @property
    def body(self):
        return b"\n".join([str(i).encode('utf-8') for i in self.sections])

    def __str__(self):
        segments = [manifest_header('Manifest'),
                    "",
                    self.body.decode('utf-8'),
                    ""]
        return "\n".join(segments)


class Signature(Manifest):
    digest_manifests = {}
    filename = 'zigbert'

    @property
    def digest_manifest(self):
        return [
            "{}-Digest-Manifest: {}".format(
                item[0].upper(),
                b64encode(item[1]).decode('utf-8')
            )
            for item in sorted(self.digest_manifests.items())
        ]

    @property
    def header(self):
        segments = [manifest_header('Signature')]
        segments.extend(self.digest_manifest)
        segments.append('')
        return "\n".join(segments).encode('utf-8')

    def __str__(self):
        return self.header + "\n"


class XPIFile(object):
    """An XPI file read from disk.

    This class represents an XPI file and its contents. It can be used
    to generate manifests such as would be found in a META-INF
    directory. These manifests can be signed, and this signature can
    be used to produce a signed XPI file.
    """

    def __init__(self, path, ids=None):
        """
        """
        self.inpath = path
        self._digests = []
        self.ids = ids

        def mksection(data, fname):
            digests = _digest(data)
            item = Section(fname, digests=digests)
            self._digests.append(item)
        def zinfo_key(zinfo):
            return file_key(zinfo.filename)
        with ZipFile(self.inpath, 'r') as zin:
            for f in sorted(zin.filelist, key=zinfo_key):
                # Skip directories and specific files found in META-INF/ that
                # are not permitted in the manifest
                if (directory_re.search(f.filename)
                        or ignore_certain_metainf_files(f.filename)):
                    continue
                mksection(zin.read(f.filename), f.filename)
            if ids:
                mksection(ids, 'META-INF/ids.json')

    @property
    @functools.lru_cache(maxsize=None)
    def manifest(self):
        return Manifest(self._digests)

    @property
    @functools.lru_cache(maxsize=None)
    def signatures(self):
        # The META-INF/*.sf files should contain hashes of the individual
        # sections of the the META-INF/manifest.mf file.  So we generate those
        # signatures here
        digest_manifest = _digest(str(self.manifest).encode('utf-8'))
        return Signature([], digest_manifests=digest_manifest)

    @property
    def signature(self):
        # Returns only the x-Digest-Manifest signature and omits the individual
        # section signatures
        return self.signatures.header + b"\n"

    def make_signed(self, outpath, sigpath, signed_manifest, signature):
        if not outpath:
            raise IOError("No output file specified")

        # FIXME: Take this out once we stop supporting 3.4 and less
        if os.path.exists(outpath):
            raise FileExistsError("File already exists: {}".format(outpath))

        # Normalize to a simple filename with no extension or prefixed
        # directory
        sigpath = os.path.splitext(os.path.basename(sigpath))[0]
        sigpath = os.path.join('META-INF', sigpath)

        with ZipFile(self.inpath, 'r') as zin:
            with ZipFile(outpath, ZIPFILE_WRITE_MODE, ZIP_DEFLATED) as zout:
                # The PKCS7 file("foo.rsa") *MUST* be the first file in the
                # archive to take advantage of Firefox's optimized downloading
                # of XPIs
                zout.writestr("{}.rsa".format(sigpath), signature)
                for f in zin.infolist():
                    # Make sure we exclude any of our signature and manifest
                    # files
                    if ignore_certain_metainf_files(f.filename):
                        continue
                    zout.writestr(f, zin.read(f.filename))
                zout.writestr("META-INF/manifest.mf", str(self.manifest))
                zout.writestr("{}.sf".format(sigpath), signed_manifest)
                if self.ids is not None:
                    zout.writestr('META-INF/ids.json', self.ids)
