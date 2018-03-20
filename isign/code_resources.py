import binascii
import copy
import hashlib
import logging
from memoizer import memoize
import os
import plistlib
import re

OUTPUT_DIRECTORY = '_CodeSignature'
OUTPUT_FILENAME = 'CodeResources'
TEMPLATE_FILENAME = 'code_resources_template.xml'
# DIGEST_ALGORITHM = "sha1"
HASH_BLOCKSIZE = 65536

# We don't maintain these rules in code_resources_template.xml because they
# are ordered and we can't rely on our plist parser to maintain the order.
_rules = [
    ( '^', True ),
    ( '^.*\\.lproj/', {'optional': True, 'weight': 1000.0} ),
    ( '^.*\\.lproj/locversion.plist$', {'omit': True, 'weight': 1100.0} ),
    ( '^Base\\.lproj/', {'weight': 1010.0}, ),
    ( '^version.plist$', True ),
]
_rules2 = [
    ( '.*\\.dSYM($|/)', {'weight': 11.0} ),
    ( '^', {'weight': 20.0} ),
    ( '^(.*/)?\\.DS_Store$', {'omit': True, 'weight': 2000.0} ),
    ( '^(Frameworks|SharedFrameworks|PlugIns|Plug-ins|XPCServices|Helpers|MacOS|Library/(Automator|Spotlight|LoginItems))/', {'nested': True, 'weight': 10.0} ),
    ( '^.*', True),
    ( '^.*\\.lproj/', {'optional': True, 'weight': 1000.0} ),
    ( '^.*\\.lproj/locversion.plist$', {'omit': True, 'weight': 1100.0} ),
    ( '^Base\\.lproj/', {'weight': 1010.0} ),
    ( '^Info\\.plist$', {'omit': True, 'weight': 20.0} ),
    ( '^PkgInfo$', {'omit': True, 'weight': 20.0} ),
    ( '^[^/]+$', {'nested': True, 'weight': 10.0} ),
    ( '^embedded\\.provisionprofile$', {'weight': 20.0} ),
    ( '^version\\.plist$', {'weight': 20.0} ),
]

log = logging.getLogger(__name__)


def rules_to_dict(rules):
    ret = {}
    for pattern, properties in rules:
        ret[pattern] = properties
    return ret


# Simple reimplementation of ResourceBuilder, in the Apple Open Source
# file bundlediskrep.cpp
class PathRule(object):
    OPTIONAL = 0x01
    OMITTED = 0x02
    NESTED = 0x04
    EXCLUSION = 0x10  # unused?
    TOP = 0x20        # unused?

    def __init__(self, pattern='', properties=None):
        # on Mac OS the FS is case-insensitive; simulate that here
        self.pattern = re.compile(pattern, re.IGNORECASE)
        self.flags = 0
        self.weight = 0
        if properties is not None:
            if type(properties) == 'bool':
                if properties is False:
                    self.flags |= PathRule.OMITTED
                # if it was true, this file is required;
                # do nothing
            elif isinstance(properties, dict):
                for key, value in properties.items():
                    if key == 'optional' and value is True:
                        self.flags |= PathRule.OPTIONAL
                    elif key == 'omit' and value is True:
                        self.flags |= PathRule.OMITTED
                    elif key == 'nested' and value is True:
                        self.flags |= PathRule.NESTED
                    elif key == 'weight':
                        self.weight = float(value)

    def is_optional(self):
        return self.flags & PathRule.OPTIONAL != 0

    def is_omitted(self):
        return self.flags & PathRule.OMITTED != 0

    def is_nested(self):
        return self.flags & PathRule.NESTED != 0

    def is_exclusion(self):
        return self.flags & PathRule.EXCLUSION != 0

    def is_top(self):
        return self.flags & PathRule.TOP != 0

    def matches(self, path):
        return re.match(self.pattern, path)

    def __str__(self):
        return 'PathRule:' + str(self.flags) + ':' + str(self.weight)

class ResourceBuilder(object):
    NULL_PATH_RULE = PathRule()

    def __init__(self, app_path, rules, respect_omissions=False, include_sha256=False):
        self.app_path = app_path
        self.app_dir = os.path.dirname(app_path)
        self.rules = []
        self.respect_omissions = respect_omissions
        self.include_sha256 = include_sha256
        for pattern, properties in rules:
            self.rules.append(PathRule(pattern, properties))

    def find_rule(self, path):
        best_rule = ResourceBuilder.NULL_PATH_RULE
        for rule in self.rules:
            log.debug('trying rule (' + str(rule.pattern.pattern) + ') w=' + str(rule.weight) + ' best w=' + str(best_rule.weight) + ' against ' + path)
            if rule.matches(path):
                if rule.flags and rule.is_exclusion():
                    best_rule = rule
                    break
                elif rule.weight >= best_rule.weight:
                    best_rule = rule
        log.debug('best rule = ' + str(rule) + ' (' + str(rule.pattern.pattern) + ') against ' + path)
        return best_rule

    def get_rule_and_paths(self, root, path):
        path = os.path.join(root, path)
        relative_path = os.path.relpath(path, self.app_dir)
        rule = self.find_rule(relative_path)
        return (rule, path, relative_path)

    def scan(self):
        """
        Walk entire directory, compile mapping
        path relative to source_dir -> digest and other data
        """
        file_entries = {}
        # rule_debug_fmt = "rule: {0}, path: {1}, relative_path: {2}"
        for root, dirs, filenames in os.walk(self.app_dir):
            # log.debug("root: {0}".format(root))
            for filename in filenames:
                rule, path, relative_path = self.get_rule_and_paths(root,
                                                                    filename)
                # log.debug(rule_debug_fmt.format(rule, path, relative_path))

                # There's no rule for the Entitlements.plist file which we
                # generate temporarily so we just ommit the file as a special
                # case...
                if relative_path == 'Entitlements.plist':
                    continue

                if rule.is_exclusion():
                    continue

                if rule.is_omitted() and self.respect_omissions is True:
                    continue

                if self.app_path == path:
                    continue

                # in the case of symlinks, we don't calculate the hash but rather add a key for it being a symlink
                if os.path.islink(path):
                    # omit symlinks from files, leave in files2
                    if not self.respect_omissions:
                        continue
                    val = {'symlink': os.readlink(path)}
                else:
                    # the Data element in plists is base64-encoded
                    val = {'hash': plistlib.Data(get_hash_binary(path))}
                    if self.include_sha256:
                        val['hash2'] = plistlib.Data(get_hash_binary(path, 'sha256'))

                if rule.is_optional():
                    val['optional'] = True

                if len(val) == 1 and 'hash' in val:
                    file_entries[relative_path] = val['hash']
                else:
                    file_entries[relative_path] = val

            for dirname in dirs:
                rule, path, relative_path = self.get_rule_and_paths(root,
                                                                    dirname)

                if rule.is_nested() and '.' not in path:
                    dirs.remove(dirname)
                    continue

                if relative_path == OUTPUT_DIRECTORY:
                    dirs.remove(dirname)

        return file_entries


def get_template():
    """
    Obtain the 'template' plist which also contains things like
    default rules about which files should count
    """
    current_dir = os.path.dirname(os.path.abspath(__file__))
    template_path = os.path.join(current_dir, TEMPLATE_FILENAME)
    # fh = open(template_path, 'r')
    return plistlib.readPlist(template_path)


@memoize
def get_hash_hex(path, hash_type='sha1'):
    """ Get the hash of a file at path, encoded as hexadecimal """
    if hash_type == 'sha256':
        hasher = hashlib.sha256()
    elif hash_type == 'sha1':
        hasher = hashlib.sha1()
    else:
        raise ValueError("Incorrect hash type provided: {}".format(hash_type))

    with open(path, 'rb') as afile:
        buf = afile.read(HASH_BLOCKSIZE)
        while len(buf) > 0:
            hasher.update(buf)
            buf = afile.read(HASH_BLOCKSIZE)
    return hasher.hexdigest()


@memoize
def get_hash_binary(path, hash_type='sha1'):
    """ Get the hash of a file at path, encoded as binary """
    return binascii.a2b_hex(get_hash_hex(path, hash_type))


def write_plist(target_dir, plist):
    """ Write the CodeResources file """
    output_dir = os.path.join(target_dir, OUTPUT_DIRECTORY)
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    output_path = os.path.join(output_dir, OUTPUT_FILENAME)
    # fh = open(output_path, 'w')
    plistlib.writePlist(plist, output_path)
    return output_path


def make_seal(source_app_path, target_dir=None):
    """
    Given a source app, create a CodeResources file for the
    surrounding directory, and write it into the appropriate path in a target
    directory
    """
    if target_dir is None:
        target_dir = os.path.dirname(source_app_path)
    template = get_template()
    print("template = " + str(template))
    # n.b. code_resources_template not only contains a template of
    # what the file should look like; it contains default rules
    # deciding which files should be part of the seal
    plist = copy.deepcopy(template)
    resource_builder = ResourceBuilder(source_app_path, _rules, respect_omissions=False)
    plist['files'] = resource_builder.scan()
    plist['rules'] = rules_to_dict(_rules)
    resource_builder2 = ResourceBuilder(source_app_path, _rules2, respect_omissions=True, include_sha256=True)
    plist['files2'] = resource_builder2.scan()
    plist['rules2'] = rules_to_dict(_rules2)
    return write_plist(target_dir, plist)
