#
# Copyright (C) 2006-2012 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=zabbix
PKG_VERSION:=1.8.12
PKG_RELEASE:=1

#PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
#PKG_SOURCE_URL:=@SF/zabbix
#PKG_MD5SUM:=6b6ced84024f18f22ce5e0e902e91936

PKG_SOURCE:=pre-zabbix-1.8.12rc1.x-26688.tar.gz
PKG_SOURCE_URL:=http://www.zabbix.com/downloads/nightly/pre-zabbix-1.8.12rc1.x-26688.tar.gz
PKG_MD5SUM:=7db3adaba214b3b004e9387f4154ca6b

PKG_BUILD_DEPENDS:=libsqlite3 $(ICONV_DEPENDS)
PKG_INSTALL:=1

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/nls.mk

define Package/zabbix/Default
  SECTION:=admin
  CATEGORY:=Administration
  TITLE:=Zabbix
  URL:=http://www.zabbix.com/
  SUBMENU:=zabbix
endef

define Package/zabbix-agent
  $(call Package/zabbix/Default)
  TITLE+= agent
endef

define Package/zabbix-sender
  $(call Package/zabbix/Default)
  TITLE+= sender
endef

define Package/zabbix-server
  $(call Package/zabbix/Default)
  TITLE+= server
  DEPENDS += +libsqlite3 +libcurl +libiconv
endef


ifneq ($(SDK),)
CONFIG_PACKAGE_zabbix-server:=m
endif

CONFIGURE_ARGS+= \
	--bindir="/usr/sbin" \
	--enable-agent \
	$(if $(CONFIG_IPV6),--enable-ipv6,--disable-ipv6)

ifneq ($(CONFIG_PACKAGE_zabbix-server),)
  CONFIGURE_ARGS+= \
	--enable-server \
	--with-sqlite3="$(STAGING_DIR)/usr"
endif

MAKE_FLAGS += ARCH="linux"

define Package/zabbix-agent/conffiles
/etc/zabbix/zabbix_agentd.conf
endef

define Package/zabbix-agent/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/sbin/zabbix_agentd $(1)/usr/sbin/
	$(INSTALL_DIR) $(1)/etc/zabbix
	$(INSTALL_CONF) ./files/zabbix_agentd.conf $(1)/etc/zabbix/
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/zabbix_agentd.init $(1)/etc/init.d/zabbix_agentd
endef

define Package/zabbix-sender/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/sbin/zabbix_sender $(1)/usr/sbin/
	$(INSTALL_DIR) $(1)/etc/zabbix
endef

define Package/zabbix-server/conffiles
/etc/zabbix/zabbix_server.conf
endef

define Package/zabbix-server/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/sbin/zabbix_server $(1)/usr/sbin/
	$(INSTALL_DIR) $(1)/etc/zabbix
	$(INSTALL_CONF) $(PKG_BUILD_DIR)/misc/conf/zabbix_server.conf $(1)/etc/zabbix/
endef

$(eval $(call BuildPackage,zabbix-agent))
$(eval $(call BuildPackage,zabbix-sender))
$(eval $(call BuildPackage,zabbix-server))
