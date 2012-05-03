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


include $(INCLUDE_DIR)/package.mk

define Package/$(PKG_NAME)/template
	SECTION:=admin
	CATEGORY:=Administration
	MAINTAINER:=Gioacchino Mazzurco <gmazzurco89@gmail.com>
	SUBMENU:=$(PKG_NAME)
endef

define Package/$(PKG_NAME)-autoconf
	$(call Package/$(PKG_NAME)/template)
	TITLE:=eigenNet Auto Config Package
	DEPENDS:=+ip +kmod-batman-adv +kmod-ipv6
endef

define Package/$(PKG_NAME)-bwtest
	$(call Package/$(PKG_NAME)/template)
	TITLE:=eigenNet Bandwidth Measurement Tool
	DEPENDS:=+pv +netcat
endef

define Package/$(PKG_NAME)-crda
	$(call Package/$(PKG_NAME)/template)
	TITLE:=eigenNet Customized CRDA
	DEPENDS:=crda
endef

define Package/$(PKG_NAME)-gw4check
	$(call Package/$(PKG_NAME)/template)
	TITLE:=eigenNet IPv4 Gateway Checker
	DEPENDS:=+ip +kmod-batman-adv
endef

#define Package/$(PKG_NAME)-pointing
#	$(call Package/$(PKG_NAME)/template)
#	TITLE:=eigenNet antenna pointing tools
#	DEPENDS:=
#endef

define Package/$(PKG_NAME)-autoconf/install
	$(CP) -a ./files/* $(1)/
	@mkdir -p $(1)/etc/init.d || true
	$(CP) build/eigennet $(1)/etc/init.d/eigennet
	@chmod +x $(1)/etc/init.d/eigennet
	@mkdir -p $(1)/etc/eigennet || true
	$(CP) build/version $(1)/etc/eigennet/version
endef

define Package/$(PKG_NAME)-bwtest/install
	@echo TODO
endef

define Package/$(PKG_NAME)-crda/install
	@mkdir -p $(1)/usr/lib/crda || true
	$(CP) build/regulatory.bin $(1)/usr/lib/crda/regulatory.bin
endef

define Package/$(PKG_NAME)-gw4check/install
	@mkdir -p $(1)/etc/init.d || true
	$(CP) build/gw4check $(1)/etc/init.d/gw4check
	@chmod +x $(1)/etc/init.d/gw4check
endef

#define Package/$(PKG_NAME)-pointing/install
#	@echo TODO
#endef

define Build/Compile
	@mkdir -p ./build || true
	@grep -v '^#\[Doc\]' src/eigennet.sh > build/eigennet
	@grep -v '^#\[Doc\]' src/gw4check.sh > build/gw4check
	@./getversion.sh $(TOPDIR)> build/version
	@./src/crda/db2bin.py build/regulatory.bin src/crda/db.txt
endef

$(eval $(call BuildPackage,$(PKG_NAME)-autoconf))
$(eval $(call BuildPackage,$(PKG_NAME)-bwtest))
$(eval $(call BuildPackage,$(PKG_NAME)-crda))
$(eval $(call BuildPackage,$(PKG_NAME)-gw4check))
#$(eval $(call BuildPackage,$(PKG_NAME)-pointing))


