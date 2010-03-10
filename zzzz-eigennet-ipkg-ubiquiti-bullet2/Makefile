# 
# Copyright (C) 2007 Ninux.org <contatti@ninux.org>
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.

include $(TOPDIR)/rules.mk

EIGENMODELNAME:="Ubiquiti Bullet2"
PKG_NAME:=eigennet-ubiquiti-bullet2
PKG_VERSION:=0.1
PKG_RELEASE:=beta

# PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
# PKG_SOURCE_URL:=http://
# PKG_MD5SUM:=
# PKG_CAT:=zcat
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(INCLUDE_DIR)/package.mk

define Package/ninux-atheros
  SECTION:=admin
  CATEGORY:=Administration
  DEPENDS:=+kmod-madwifi +kmod-ipv6 +ahcpd +olsrd +bash +tcpdump +nano @TARGET_atheros 
  TITLE:=EigenNet Community Config Package $(EIGENMODELNAME)
endef

define Package/$(PKG_NAME)/install
	$(CP) -a ./files/* $(1)/
	$(SED) 's,$$$$R,$(REVISION),g' $(1)/etc/banner 
	mkdir -p $(1)/CONTROL
	$(CP) -a ./ipkg/$(PKG_NAME).postinst $(1)/CONTROL/postinst
	$(CP) -a ./ipkg/$(PKG_NAME).prerm $(1)/CONTROL/prerm
endef

define Package/$(PKG_NAME)/description
  Prepara la $(EIGENMODELNAME) per la rete EigenNet 
endef

define Build/Compile
endef

$(eval $(call BuildPackage,$(PKG_NAME)))

