#
# Copyright (C) 2010-2011  Gioacchino Mazzurco <gmazzurco89@gmail.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this file.  If not, see <http://www.gnu.org/licenses/>.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=eigennet-autoconf
PKG_VERSION:=0.4.1
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(INCLUDE_DIR)/package.mk

define Package/$(PKG_NAME)
  SECTION:=admin
  CATEGORY:=Administration
  MAINTAINER:=Gioacchino Mazzurco <gmazzurco89@gmail.com>
  DEPENDS:=+ip +kmod-batman-adv +kmod-ipv6 +eigen-mini-snmpd
  TITLE:=EigenNet Auto Config Package
endef

define Package/$(PKG_NAME)/install
	$(CP) -a ./files/* $(1)/
endef

define Package/$(PKG_NAME)/description
  Prepare Node for EigenNet 
endef

define Build/Compile
	@echo "Version Info:"			>  ./version.tmp
	@echo ""				>> ./version.tmp
	@echo "OpenWrt"				>> ./version.tmp
	@echo "`cd $(TOPDIR); svn info`"	>> ./version.tmp
	@echo ""				>> ./version.tmp
	@echo "Feeds"				>> ./version.tmp
	@grep -v '^#' $(TOPDIR)/feeds.conf | grep src | while read line; do echo "" ; srcsvc="$(echo $line | awk '{print $1}' | awk -F- '{print $2}')"; srcdir="$(echo $line | awk '{print $2}')"; case "$srcsvc" in svn) echo "`cd $(TOPDIR)/feeds/$srcdir; svn info`" ; ;; git) echo "`cd $(TOPDIR)/feeds/$srcdir; git branch`" ; echo "`cd $(TOPDIR)/feeds/$srcdir; git log -n 1`" ; ;; esac; done >> ./version.tmp
	@mkdir ./files/etc/eigennet &> /dev/null || true
	@mv ./version.tmp ./files/etc/eigennet/version
endef

$(eval $(call BuildPackage,$(PKG_NAME)))


