import pkg_resources


__all__ = ['version_info', 'version']

try:
    # First, try to get our version out of PKG-INFO. If we're installed,
    # this'll let us find our version without pulling in pbr. After all, if
    # we're installed on a system, we're not in a Git-managed source tree, so
    # pbr doesn't really buy us anything.
    __version__ = pkg_resources.get_provider(
        pkg_resources.Requirement.parse('oss2swift')).version
except pkg_resources.DistributionNotFound:
    # No PKG-INFO? We're probably running from a checkout, then. Let pbr do
    # its thing to figure out a version number.
    import pbr.version
    __version__ = pbr.version.VersionInfo('oss2swift').release_string()

#: Version information ``(major, minor, revision)``.
version_info = tuple(map(int, __version__.split('.')[:3]))
#: Version string ``'major.minor.revision'``.
version = '.'.join(map(str, version_info))

