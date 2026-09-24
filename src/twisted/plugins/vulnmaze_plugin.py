"""twistd plugin: `twistd -n vulnmaze` runs Cowrie with the VulnMaze hooks.

Twisted discovers this file because it lives in a `twisted/plugins/`
directory on sys.path (the package is installed with it). It reuses Cowrie's
own service maker unchanged and only installs our hooks first.
"""

from __future__ import annotations

from typing import ClassVar

from twisted.application.service import IServiceMaker
from twisted.plugin import IPlugin
from twisted.plugins.cowrie_plugin import CowrieServiceMaker
from zope.interface import implementer


@implementer(IServiceMaker, IPlugin)
class VulnMazeServiceMaker(CowrieServiceMaker):
    tapname: ClassVar[str] = "vulnmaze"
    description: ClassVar[str] = "Cowrie with the VulnMaze router"

    def makeService(self, options):  # noqa: N802 (Twisted's name)
        from vulnmaze.cowrie_ext.hooks import install

        install()
        return super().makeService(options)


serviceMaker = VulnMazeServiceMaker()
