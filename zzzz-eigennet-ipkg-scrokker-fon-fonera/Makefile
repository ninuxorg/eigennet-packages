#
#Copyright (C) 2010  Gioacchino Mazzurco <gmazzurco89@gmail.com>
#
#This program is free software: you can redistribute it and/or modify
#it under the terms of the GNU General Public License as published by
#the Free Software Foundation, either version 3 of the License, or
#(at your option) any later version.
#
#This program is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU General Public License for more details.
#
#You should have received a copy of the GNU General Public License
#along with this file.  If not, see <http://www.gnu.org/licenses/>.



include $(TOPDIR)/rules.mk

EIGENMODELNAME:=Fonera
PKG_NAME:=eigennet-scrokker-fon-fonera
PKG_VERSION:=0.1
PKG_RELEASE:=beta

# PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
# PKG_SOURCE_URL:=http://
# PKG_MD5SUM:=
# PKG_CAT:=zcat
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(INCLUDE_DIR)/package.mk

define Package/$(PKG_NAME)
  SECTION:=admin
  CATEGORY:=Administration
  DEPENDS:=+kmod-madwifi +iptables-mod-nat +iptables-mod-nat-extra +kmod-ipt-nat +kmod-ipt-nat-extra +wpa-supplicant +hostapd +dhcpcd @TARGET_atheros 
  #+bash 
  TITLE:= $(EIGENMODELNAME) Scrokker Config Package
endef

define Package/$(PKG_NAME)/install
	$(CP) -a ./files/* $(1)/
#	$(SED) 's,$$$$R,$(REVISION),g' $(1)/etc/banner 
	mkdir -p $(1)/CONTROL
#	$(CP) -a ./ipkg/$(PKG_NAME).postinst $(1)/CONTROL/postinst
#	$(CP) -a ./ipkg/$(PKG_NAME).prerm $(1)/CONTROL/prerm
endef

define Package/$(PKG_NAME)/description
  Prepare $(EIGENMODELNAME) for scrokking
endef

define Build/Compile
endef

$(eval $(call BuildPackage,$(PKG_NAME)))

