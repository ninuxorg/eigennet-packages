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
PKG_VERSION:=0.4
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(INCLUDE_DIR)/package.mk

define Package/$(PKG_NAME)
  SECTION:=admin
  CATEGORY:=Administration
  MAINTAINER:=Gioacchino Mazzurco <gmazzurco89@gmail.com>
  DEPENDS:=+kmod-ipv6 +kmod-batman-adv +ip
  TITLE:=EigenNet Auto Config Package
endef

define Package/$(PKG_NAME)/install
	$(CP) -a ./files/* $(1)/
endef

define Package/$(PKG_NAME)/description
  Prepare Node for EigenNet 
endef

define Build/Compile
endef

$(eval $(call BuildPackage,$(PKG_NAME)))


