#
# Copyright (C) 2007-2009 OpenWrt.org
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

PKG_NAME:=mcrypt
PKG_VERSION:=2.6.8
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=@SF/mcrypt
PKG_MD5SUM:=97639f8821b10f80943fa17da302607e

include $(INCLUDE_DIR)/package.mk

define Package/$(PKG_NAME)
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=mcrypt simple encryption program
  URL:=http://mcrypt.sourceforge.net/
  DEPENDS:=+libmcrypt
endef

define Package/$(PKG_NAME)/description
	mcrypt is a simple encryption program intended to be replacement for the old unix crypt
endef

define Build/Configure
	$(call Build/Configure/Default, \
		--enable-shared \
		--enable-static \
	)
endef

define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/mcrypt $(1)/usr/bin/
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
