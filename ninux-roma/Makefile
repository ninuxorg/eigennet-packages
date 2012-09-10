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
PKG_VERSION:=0.5.1
PKG_RELEASE:=2


include $(INCLUDE_DIR)/package.mk

define Package/$(PKG_NAME)/template
	SECTION:=admin
	CATEGORY:=Administration
	MAINTAINER:=Gioacchino Mazzurco <gmazzurco89@gmail.com>
	SUBMENU:=$(PKG_NAME)
endef

define Package/$(PKG_NAME)-autoconf
	$(call Package/$(PKG_NAME)/template)
	TITLE:=Auto Config Package
	DEPENDS:=+ip +kmod-ipv6 +iw +iptables +iputils-arping +iputils-ping +iputils-ping6 +iputils-traceroute6 +iwinfo +olsrd-ninux +olsrd-ninux-mod-httpinfo +olsrd-ninux-mod-mdns +olsrd-ninux-mod-nameservice +olsrd-ninux-mod-txtinfo +radvd +tcpdump-mini +wpa-supplicant-mini +wpad-mini +hostapd-mini +nodogsplashninux +iptables-mod-ipopt +libpthread +mini-snmpd
endef

define Package/$(PKG_NAME)-bwtest
	$(call Package/$(PKG_NAME)/template)
	TITLE:=Bandwidth Measurement Tool (need busybox nc -l)
	DEPENDS:=+pv
endef

define Package/$(PKG_NAME)-bwtest-webui
	$(call Package/$(PKG_NAME)/template)
	TITLE:=Bandwidth Measurement Tool (need busybox nc -l)
	DEPENDS:=+$(PKG_NAME)-bwtest +uhttpd
endef

define Package/$(PKG_NAME)-crda
	$(call Package/$(PKG_NAME)/template)
	TITLE:=Customized CRDA ( DEPRECATED )
	DEPENDS:=crda
endef

define Package/$(PKG_NAME)-firewall
	$(call Package/$(PKG_NAME)/template)
	TITLE:=EigenNet Firewall
	DEPENDS:=+ebtables +kmod-ebtables-ipv4 +kmod-ebtables-ipv6
endef

define Package/$(PKG_NAME)-gw4server
	$(call Package/$(PKG_NAME)/template)
	TITLE:=IPv4 Gateway Checker
	DEPENDS:=+ip
endef

define Package/$(PKG_NAME)-httpinfo
	$(call Package/$(PKG_NAME)/template)
	TITLE:=Export info via HTTP protocol
	DEPENDS:=+uhttpd
endef

define Package/$(PKG_NAME)-pointing
	$(call Package/$(PKG_NAME)/template)
	TITLE:=Antenna Pointing Tools
endef

define Package/$(PKG_NAME)-pointing-webui
	$(call Package/$(PKG_NAME)/template)
	TITLE:=eigenNet antenna pointing tools
	DEPENDS:=+$(PKG_NAME)-pointing +uhttpd
endef

define Package/$(PKG_NAME)-reghack
	$(call Package/$(PKG_NAME)/template)
	TITLE:=eigenNet regulatory domain unlocker
endef

define Package/$(PKG_NAME)-autoconf/install
	$(CP) -a ./files/* $(1)/
	@mkdir -p $(1)/etc/init.d || true
	$(CP) build/eigennet $(1)/etc/init.d/eigennet
	@chmod +x $(1)/etc/init.d/eigennet
	@mkdir -p $(1)/etc/eigennet || true
	$(CP) build/version $(1)/etc/eigennet/version
endef

define Package/$(PKG_NAME)-bwtest/install
	@mkdir -p $(1)/etc/init.d || true
	$(CP) build/bwtserver $(1)/etc/init.d/bwtserver
	@chmod +x $(1)/etc/init.d/bwtserver
endef

define Package/$(PKG_NAME)-bwtest-webui/install
	@mkdir -p $(1)/www/cgi-bin || true
	$(CP) src/index.html $(1)/www/index.html
	$(CP) src/bwtclient.cgi $(1)/www/cgi-bin/bwtclient.cgi
	@chmod +x $(1)/www/cgi-bin/bwtclient.cgi
	$(CP) src/startbwt.cgi $(1)/www/cgi-bin/startbwt.cgi
	@chmod +x $(1)/www/cgi-bin/startbwt.cgi
endef

define Package/$(PKG_NAME)-crda/install
	@mkdir -p $(1)/usr/lib/crda || true
	$(CP) build/regulatory.bin $(1)/usr/lib/crda/regulatory.bin
endef

define Package/$(PKG_NAME)-firewall/install
	@mkdir -p $(1)/etc/eigennet/firewall-disabled-modules.d/ || true
endef

define Package/$(PKG_NAME)-gw4server/install
	@mkdir -p $(1)/etc/init.d || true
	$(CP) build/gw4server $(1)/etc/init.d/gw4server
	@chmod +x $(1)/etc/init.d/gw4server
endef

define Package/$(PKG_NAME)-httpinfo/install
	@mkdir -p $(1)/www/cgi-bin || true
	$(CP) src/getdBm.cgi $(1)/www/cgi-bin/getdBm.cgi
	@chmod +x $(1)/www/cgi-bin/getdBm.cgi
	$(CP) src/ifstat.cgi $(1)/www/cgi-bin/ifstat.cgi
	@chmod +x $(1)/www/cgi-bin/ifstat.cgi
endef

define Package/$(PKG_NAME)-pointing/install
	@mkdir -p $(1)/usr/lib/eigennet || true
	$(CP) build/links.sh $(1)/usr/lib/eigennet/links.sh
	@chmod +x $(1)/usr/lib/eigennet/links.sh
endef

define Package/$(PKG_NAME)-pointing-webui/install
	@mkdir -p $(1)/www/cgi-bin || true
	$(CP) src/index.html $(1)/www/index.html
	$(CP) src/pointing.cgi $(1)/www/cgi-bin/pointing.cgi
	@chmod +x $(1)/www/cgi-bin/pointing.cgi
endef

define Package/$(PKG_NAME)-reghack/install
	@mkdir -p $(1)/usr/bin
	$(CP) build/reghack $(1)/usr/bin/reghack
	@chmod +x $(1)/usr/bin/reghack
	@mkdir -p $(1)/etc/uci-defaults
	$(CP) src/reghack.sh $(1)/etc/uci-defaults/eigennet-reghack.sh
	@chmod +x $(1)/etc/uci-defaults/eigennet-reghack.sh
endef

define Build/Compile
	@mkdir -p ./build || true
	@grep -v '^#\[Doc\]' src/eigennet.sh > build/eigennet
	@grep -v '^#\[Doc\]' src/gw4server.sh > build/gw4server
	@grep -v '^#\[Doc\]' src/links.sh > build/links.sh
	@grep -v '^#\[Doc\]' src/bwtserver.sh > build/bwtserver
	@./getversion.sh $(TOPDIR)> build/version
	@./src/crda/db2bin.py build/regulatory.bin src/crda/db.txt
	$(TARGET_CC) src/reghack.c -o build/reghack
endef

$(eval $(call BuildPackage,$(PKG_NAME)-autoconf))
$(eval $(call BuildPackage,$(PKG_NAME)-bwtest))
$(eval $(call BuildPackage,$(PKG_NAME)-bwtest-webui))
$(eval $(call BuildPackage,$(PKG_NAME)-crda))
$(eval $(call BuildPackage,$(PKG_NAME)-firewall))
$(eval $(call BuildPackage,$(PKG_NAME)-gw4server))
$(eval $(call BuildPackage,$(PKG_NAME)-httpinfo))
$(eval $(call BuildPackage,$(PKG_NAME)-pointing))
$(eval $(call BuildPackage,$(PKG_NAME)-pointing-webui))
$(eval $(call BuildPackage,$(PKG_NAME)-reghack))
