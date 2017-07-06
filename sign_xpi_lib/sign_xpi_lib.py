# -*- coding: utf-8 -*-

"""Main module."""

import fnmatch
import hashlib
import os.path
import re
from zipfile import ZipFile, ZIP_DEFLATED
from base64 import b64encode


directory_re = re.compile(r"[\\/]$")


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


def file_key(zinfo):
    '''
    Sort keys for xpi files
    @param name: name of the file to generate the sort key from
    '''
    # Copied from xpisign.py's api.py and tweaked
    name = zinfo.filename
    prio = 4
    if name == 'install.rdf':
        prio = 1
    elif name in ["chrome.manifest", "icon.png", "icon64.png"]:
        prio = 2
    elif name in ["MPL", "GPL", "LGPL", "COPYING", "LICENSE", "license.txt"]:
        prio = 5
    parts = [prio] + list(os.path.split(name.lower()))
    return "%d-%s-%s" % tuple(parts)


def _digest(data):
    md5 = hashlib.md5()
    md5.update(data)
    sha1 = hashlib.sha1()
    sha1.update(data)
    return {'md5': md5.digest(), 'sha1': sha1.digest()}


class Section(object):
    __slots__ = ('name', 'algos', 'digests')

    def __init__(self, name, algos=('md5', 'sha1'), digests={}):
        self.name = name
        self.algos = algos
        self.digests = digests

    def __str__(self):
        # Important thing to note: placement of newlines in these strings is
        # sensitive and should not be changed without reading through
        # http://docs.oracle.com/javase/7/docs/technotes/guides/jar/jar.html#JAR%20Manifest
        # thoroughly.
        algos = ''
        order = list(self.digests.keys())
        order.sort()
        for algo in order:
            algos += ' %s' % algo.upper()
        entry = ''
        # The spec for zip files only supports extended ASCII and UTF-8
        # See http://www.pkware.com/documents/casestudies/APPNOTE.TXT
        # and search for "language encoding" for details
        #
        # See https://bugzilla.mozilla.org/show_bug.cgi?id=1013347
        name = 'Name: %s' % self.name

        # See https://bugzilla.mozilla.org/show_bug.cgi?id=841569#c35
        while name:
            entry += name[:72]
            name = name[72:]
            if name:
                entry += '\n '
        entry += '\n'
        entry += 'Digest-Algorithms:%s\n' % algos
        for algo in order:
            entry += '%s-Digest: %s\n' % (algo.upper(),
                                          b64encode(self.digests[algo]).decode('utf-8'))
        return entry


class Manifest(list):
    version = '1.0'
    # Older versions of Firefox crash if a JAR manifest style file doesn't
    # end in a blank line("\n\n").  For more details see:
    # https://bugzilla.mozilla.org/show_bug.cgi?id=1158467

    def __init__(self, *args, **kwargs):
        super(Manifest, self).__init__(*args)
        for k, v in kwargs.items():
            setattr(self, k, v)

    @property
    def header(self):
        return b"%s-Version: %s" % (
            type(self).__name__.title().encode('utf-8'),
            self.version.encode('utf-8'))

    @property
    def body(self):
        return b"\n".join([str(i).encode('utf-8') for i in self])

    def __str__(self):
        segments = [self.header.decode('utf-8'),
                    "",
                    self.body.decode('utf-8'),
                    ""]
        return "\n".join(segments)


class Signature(Manifest):
    digest_manifests = {}
    filename = 'zigbert'

    @property
    def digest_manifest(self):
        return [b"%s-Digest-Manifest: %s" %
                (item[0].upper().encode('utf-8'), b64encode(item[1]))
                for item in sorted(self.digest_manifests.items())]

    @property
    def header(self):
        segments = [super(Signature, self).header]
        segments.extend(self.digest_manifest)
        segments.append(b"")
        return b"\n".join(segments)

    def __str__(self):
        return self.header.decode('utf-8') + "\n"


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
        self._manifest = None
        self._sig = None
        self.ids = ids

        def mksection(data, fname):
            digests = _digest(data)
            item = Section(fname, algos=tuple(digests.keys()),
                           digests=digests)
            self._digests.append(item)
        with ZipFile(self.inpath, 'r') as zin:
            for f in sorted(zin.filelist, key=file_key):
                # Skip directories and specific files found in META-INF/ that
                # are not permitted in the manifest
                if (directory_re.search(f.filename)
                        or ignore_certain_metainf_files(f.filename)):
                    continue
                mksection(zin.read(f.filename), f.filename)
            if ids:
                mksection(ids, 'META-INF/ids.json')

    def _sign(self, item):
        digests = _digest(str(item).encode('utf-8'))
        return Section(item.name, algos=tuple(digests.keys()),
                       digests=digests)

    @property
    def manifest(self):
        if not self._manifest:
            self._manifest = Manifest(self._digests)
        return self._manifest

    @property
    def signatures(self):
        # The META-INF/*.sf files should contain hashes of the individual
        # sections of the the META-INF/manifest.mf file.  So we generate those
        # signatures here
        if not self._sig:
            self._sig = Signature([self._sign(f) for f in self._digests],
                                  digest_manifests=_digest(str(self.manifest).encode('utf-8')))
        return self._sig

    @property
    def signature(self):
        # Returns only the x-Digest-Manifest signature and omits the individual
        # section signatures
        return self.signatures.header + b"\n"

    def make_signed(self, outpath, sigpath, signed_manifest, signature):
        if not outpath:
            raise IOError("No output file specified")

        if os.path.exists(outpath):
            raise IOError("File already exists: %s" % outpath)

        sigpath = sigpath
        # Normalize to a simple filename with no extension or prefixed
        # directory
        sigpath = os.path.splitext(os.path.basename(sigpath))[0]
        sigpath = os.path.join('META-INF', sigpath)

        with ZipFile(self.inpath, 'r') as zin:
            with ZipFile(outpath, 'w', ZIP_DEFLATED) as zout:
                # The PKCS7 file("foo.rsa") *MUST* be the first file in the
                # archive to take advantage of Firefox's optimized downloading
                # of XPIs
                zout.writestr("%s.rsa" % sigpath, signature)
                for f in zin.infolist():
                    # Make sure we exclude any of our signature and manifest
                    # files
                    if ignore_certain_metainf_files(f.filename):
                        continue
                    zout.writestr(f, zin.read(f.filename))
                zout.writestr("META-INF/manifest.mf", str(self.manifest))
                zout.writestr("%s.sf" % sigpath, signed_manifest)
                if self.ids is not None:
                    zout.writestr('META-INF/ids.json', self.ids)
