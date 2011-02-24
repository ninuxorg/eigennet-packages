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

PKG_NAME:=olsrd-eigennet
PKG_VERSION:=0.6.1
PKG_RELEASE:=3

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)/
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
PKG_SOURCE_URL:=git://olsr.org/olsrd.git
PKG_SOURCE_VERSION:=origin/stable
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

TARGET_CFLAGS += $(FPIC)

define Package/$(PKG_NAME)/template
  SECTION:=net
  CATEGORY:=Network
  TITLE:=OLSR daemon from git stable for Eigennet
  URL:=http://www.olsr.org/
endef

define Package/$(PKG_NAME)
  $(call Package/$(PKG_NAME)/template)
  MENU:=1
  DEPENDS:=+libpthread
endef

define Package/$(PKG_NAME)/conffiles
/etc/config/olsrd
endef

define Package/$(PKG_NAME)-mod-arprefresh
  $(call Package/$(PKG_NAME)/template)
  DEPENDS:=$(PKG_NAME)
  TITLE:=Kernel ARP cache refresh plugin
endef

define Package/$(PKG_NAME)-mod-dot-draw
  $(call Package/$(PKG_NAME)/template)
  DEPENDS:=$(PKG_NAME)
  TITLE:=Dot topology information plugin
endef

define Package/$(PKG_NAME)-mod-bmf
  $(call Package/$(PKG_NAME)/template)
  DEPENDS:=$(PKG_NAME) +kmod-tun
  TITLE:=Basic multicast forwarding plugin
endef

define Package/$(PKG_NAME)-mod-dyn-gw
  $(call Package/$(PKG_NAME)/template)
  DEPENDS:=$(PKG_NAME)
  TITLE:=Dynamic internet gateway plugin
endef

define Package/$(PKG_NAME)-mod-dyn-gw-plain
  $(call Package/$(PKG_NAME)/template)
  DEPENDS:=$(PKG_NAME)
  TITLE:=Dynamic internet gateway plain plugin
endef

define Package/$(PKG_NAME)-mod-httpinfo
  $(call Package/$(PKG_NAME)/template)
  DEPENDS:=$(PKG_NAME)
  TITLE:=Small informative web server plugin
endef

define Package/$(PKG_NAME)-mod-nameservice
  $(call Package/$(PKG_NAME)/template)
  DEPENDS:=$(PKG_NAME)
  TITLE:=Lightweight hostname resolver plugin
endef

define Package/$(PKG_NAME)-mod-secure
  $(call Package/$(PKG_NAME)/template)
  DEPENDS:=$(PKG_NAME)
  TITLE:=Plugin to secure routing domain
endef

define Package/$(PKG_NAME)-mod-secure/conffiles
/etc/olsrd.d/olsrd_secure_key
endef

define Package/$(PKG_NAME)-mod-txtinfo
  $(call Package/$(PKG_NAME)/template)
  DEPENDS:=$(PKG_NAME)
  TITLE:=Small informative web server plugin
endef

define Package/$(PKG_NAME)-mod-mdns
  $(call Package/$(PKG_NAME)/template)
  DEPENDS:=$(PKG_NAME)
  TITLE:=MDNS/Zeroconf/Bonjour packet distribution
endef

define Package/$(PKG_NAME)-mod-p2pd
  $(call Package/$(PKG_NAME)/template)
  DEPENDS:=$(PKG_NAME)
  TITLE:=Service discovery UDP packet distribution
endef

define Package/$(PKG_NAME)-mod-quagga
  $(call Package/$(PKG_NAME)/template)
  DEPENDS:=$(PKG_NAME)
  TITLE:=Quagga plugin for olsrd
endef

define Build/Configure
endef

define Build/Compile
	rm -rf $(PKG_INSTALL_DIR)
	mkdir -p $(PKG_INSTALL_DIR)
	$(MAKE) -C "$(PKG_BUILD_DIR)" \
		$(TARGET_CONFIGURE_OPTS) \
		NODEBUG=1 \
		CFLAGS="$(TARGET_CFLAGS)" \
		OS="linux" \
		INSTALL_PREFIX="$(PKG_INSTALL_DIR)" \
		LIBDIR="$(PKG_INSTALL_DIR)/usr/lib" \
		SBINDIR="$(PKG_INSTALL_DIR)/usr/sbin/" \
		ETCDIR="$(PKG_INSTALL_DIR)/etc" \
		MANDIR="$(PKG_INSTALL_DIR)/usr/share/man" \
		STRIP="true" \
		INSTALL_LIB="true" \
		SUBDIRS="arprefresh bmf dot_draw dyn_gw dyn_gw_plain httpinfo nameservice secure txtinfo mdns p2pd quagga" \
		all libs install install_libs
endef

define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DATA) ./files/olsrd.config $(1)/etc/config/olsrd
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/olsrd $(1)/usr/sbin/
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/olsrd.init $(1)/etc/init.d/olsrd
endef

define Package/$(PKG_NAME)-mod-arprefresh/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/lib/arprefresh/olsrd_arprefresh.so.* $(1)/usr/lib/
endef

define Package/$(PKG_NAME)-mod-dot-draw/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/lib/dot_draw/olsrd_dot_draw.so.* $(1)/usr/lib/
endef

define Package/$(PKG_NAME)-mod-bmf/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/lib/bmf/olsrd_bmf.so.* $(1)/usr/lib/
endef

define Package/$(PKG_NAME)-mod-dyn-gw/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/lib/dyn_gw/olsrd_dyn_gw.so.* $(1)/usr/lib/
endef

define Package/$(PKG_NAME)-mod-dyn-gw-plain/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/lib/dyn_gw_plain/olsrd_dyn_gw_plain.so.* $(1)/usr/lib/
endef

define Package/$(PKG_NAME)-mod-httpinfo/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/lib/httpinfo/olsrd_httpinfo.so.* $(1)/usr/lib/
endef

define Package/$(PKG_NAME)-mod-nameservice/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/lib/nameservice/olsrd_nameservice.so.* $(1)/usr/lib/
endef

define Package/$(PKG_NAME)-mod-secure/install
	$(INSTALL_DIR) $(1)/etc/olsrd.d
	$(CP) ./files/olsrd_secure_key $(1)/etc/olsrd.d/
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/lib/secure/olsrd_secure.so.* $(1)/usr/lib/
endef

define Package/$(PKG_NAME)-mod-txtinfo/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/lib/txtinfo/olsrd_txtinfo.so.* $(1)/usr/lib/
endef

define Package/$(PKG_NAME)-mod-mdns/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/lib/mdns/olsrd_mdns.so.* $(1)/usr/lib/
endef

define Package/$(PKG_NAME)-mod-p2pd/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/lib/p2pd/olsrd_p2pd.so.* $(1)/usr/lib/
endef

define Package/$(PKG_NAME)-mod-quagga/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/lib/quagga/olsrd_quagga.so.* $(1)/usr/lib/
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
$(eval $(call BuildPackage,$(PKG_NAME)-mod-arprefresh))
$(eval $(call BuildPackage,$(PKG_NAME)-mod-dot-draw))
$(eval $(call BuildPackage,$(PKG_NAME)-mod-bmf))
$(eval $(call BuildPackage,$(PKG_NAME)-mod-dyn-gw))
$(eval $(call BuildPackage,$(PKG_NAME)-mod-dyn-gw-plain))
$(eval $(call BuildPackage,$(PKG_NAME)-mod-httpinfo))
$(eval $(call BuildPackage,$(PKG_NAME)-mod-nameservice))
$(eval $(call BuildPackage,$(PKG_NAME)-mod-secure))
$(eval $(call BuildPackage,$(PKG_NAME)-mod-txtinfo))
$(eval $(call BuildPackage,$(PKG_NAME)-mod-mdns))
$(eval $(call BuildPackage,$(PKG_NAME)-mod-p2pd))
$(eval $(call BuildPackage,$(PKG_NAME)-mod-quagga))
