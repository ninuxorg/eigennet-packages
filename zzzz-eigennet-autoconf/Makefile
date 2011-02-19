#
# Copyright (C) 2010  Gioacchino Mazzurco <gmazzurco89@gmail.com>
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
PKG_VERSION:=0.3.8
PKG_RELEASE:=3

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)/
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install/

include $(INCLUDE_DIR)/package.mk

define Package/$(PKG_NAME)/template
  SECTION:=admin
  CATEGORY:=Administration
  TITLE:=EigenNet Autoconfig Package
  URL:=http://www.eigenlab.org/
endef

define Package/$(PKG_NAME)
  $(call Package/$(PKG_NAME)/template)
  DEPENDS:=+kmod-niit +bash +ip +olsrd-eigennet +olsrd-eigennet-mod-txtinfo +olsrd-eigennet-mod-mdns +dnsmasq +radvd
endef

define Package/$(PKG_NAME)/install
  $(CP) -a ./files/* $(1)/
endef

define Build/Compile
  rm -rf $(PKG_INSTALL_DIR)
  mkdir -p $(PKG_INSTALL_DIR)
endef

$(eval $(call BuildPackage,$(PKG_NAME)))

