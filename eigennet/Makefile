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

PKG_NAME:=eigennet
PKG_VERSION:=0.5
PKG_RELEASE:=1

PKG_INSTALL:=1

include $(INCLUDE_DIR)/package.mk

define Package/$(PKG_NAME)/template
	SECTION:=admin
	CATEGORY:=Administration
	MAINTAINER:=Gioacchino Mazzurco <gmazzurco89@gmail.com>
	TITLE:=eigenNet Auto Config Package
	SUBMENU:=$(PKG_NAME)
endef

define Package/$(PKG_NAME)-autoconf
	$(call Package/$(PKG_NAME)/template)
	DEPENDS:=+ip +kmod-batman-adv +kmod-ipv6
endef

define Package/$(PKG_NAME)-crda
	$(call Package/$(PKG_NAME)/template)
endef

define Package/$(PKG_NAME)-gw4check
	$(call Package/$(PKG_NAME)/template)
	DEPENDS:=+kmod-batman-adv
endef

define Package/$(PKG_NAME)-pointing
	$(call Package/$(PKG_NAME)/template)
#	DEPENDS:=$(PKG_NAME)
endef

define Package/$(PKG_NAME)-autoconf/install
	$(CP) -a ./files/* $(1)/
	@mkdir -p $(1)/etc/init.d || true
	@mv build/eigennet $(1)/etc/init.d/eigennet
	@chmod +x $(1)/etc/init.d/eigennet
	@mkdir -p $(1)/etc/eigennet || true
	@mv build/version $(1)/etc/eigennet/version
endef

define Package/$(PKG_NAME)-crda/install
	@mv build/regulatory.bin $(1)/usr/lib/crda/regulatory.bin
endef

define Package/$(PKG_NAME)-gw4check/install
	@echo TODO
endef

define Package/$(PKG_NAME)-pointing/install
	@echo TODO
endef

define Build/Compile
	@mkdir -p ./build
	@grep -v '^#\[Doc\]' src/eigennet.sh > build/eigennet
	@grep -v '^#\[Doc\]' src/gw4check.sh > build/gw4check
	@./getversion.sh $(TOPDIR)> build/version
	@./src/crda/db2bin.py build/regulatory.bin src/crda/db.txt
endef

$(eval $(call BuildPackage,$(PKG_NAME)-autoconf))
$(eval $(call BuildPackage,$(PKG_NAME)-crda))
$(eval $(call BuildPackage,$(PKG_NAME)-gw4check))
$(eval $(call BuildPackage,$(PKG_NAME)-pointing))


