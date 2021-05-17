#
# This software is licensed under the Public Domain.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=wakeondns
PKG_VERSION:=0.1
PKG_RELEASE:=1

PKG_MAINTAINER:=Lukas Meyer
PKG_LICENSE:=CC0-1.0

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

define Package/wakeondns
	SECTION:=utils
	# Select package by default
	#DEFAULT:=y
	CATEGORY:=Utilities
	PKG_BUILD_DEPENDS:=libstdcpp libpcap
	DEPENDS:=libstdcpp libpcap
	TITLE:=WakeOnDNS
	URL:=https://www.example.com
endef

define Package/wakeondns/description
	A simple daemon to wake hosts with WakeOnLan (WOL) if someone query's it's dns.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Package/wakeondns/install
	$(CP) ./files/* $(1)/

	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/wakeondns $(1)/usr/bin/
endef

$(eval $(call BuildPackage,wakeondns))