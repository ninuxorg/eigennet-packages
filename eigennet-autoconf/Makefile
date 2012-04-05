#
# Copyright (C) 2010-2012  Gioacchino Mazzurco <gmazzurco89@gmail.com>
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
PKG_VERSION:=0.4.3
PKG_RELEASE:=3

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(INCLUDE_DIR)/package.mk

define Package/$(PKG_NAME)
  SECTION:=admin
  CATEGORY:=Administration
  MAINTAINER:=Gioacchino Mazzurco <gmazzurco89@gmail.com>
  DEPENDS:=+ip +kmod-batman-adv +kmod-ipv6 +zabbix-agent
  TITLE:=EigenNet Auto Config Package
endef

define Package/$(PKG_NAME)/install
	$(CP) -a ./files/* $(1)/
endef

define Package/$(PKG_NAME)/description
  Prepare Node for EigenNet 
endef

define Build/Compile
	@grep -v '^#\[Doc\]' src/eigennet.sh > eigennet.tmp
	@mkdir -p ./files/etc/init.d || true
	@mv ./eigennet.tmp ./files/etc/init.d/eigennet
	@chmod +x ./files/etc/init.d/eigennet
	@grep -v '^#\[Doc\]' src/gw4check.sh > gw4check.tmp
	@mkdir -p ./files/usr/bin || true
	@mv ./gw4check.tmp ./files/usr/bin/gw4check
	@chmod +x ./files/usr/bin/gw4check
	@./getversion.sh $(TOPDIR)> ./version.tmp
	@mkdir ./files/etc/eigennet || true
	@mv ./version.tmp ./files/etc/eigennet/version
	@cp ./src/crda/regulatory.bin ./files/etc/eigennet/regulatory.bin
endef

$(eval $(call BuildPackage,$(PKG_NAME)))


