# ****************************************************************************
#    Ledger App Bitcoin
#    (c) 2023 Ledger SAS.
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
# ****************************************************************************

########################################
#        Mandatory configuration       #
########################################

# Application version
APPVERSION_M = 2
APPVERSION_N = 0
APPVERSION_P = 0
APPVERSION = "$(APPVERSION_M).$(APPVERSION_N).$(APPVERSION_P)"

APPDEVELOPPER="Tomo"
APPCOPYRIGHT="(c) 2025 Tomo"

VARIANT_VALUES = BBNST BBNST_test

# Application source files
# There is no additional sources for bitcoin
#APP_SOURCE_PATH += src/

# simplify for tests
ifndef COIN
COIN=BBNST_test
endif

# Enabling DEBUG flag will enable PRINTF and disable optimizations
DEBUG = 1

APP_DESCRIPTION ="This app enables staking Bitcoin with Babylon"

ifeq ($(COIN),BBNST)
APPNAME ="Babylon BTC Staking"
BITCOIN_NETWORK =mainnet
 DEFINES   += BIP32_PUBKEY_VERSION=0x0488B21E

else ifeq ($(COIN),BBNST_test)
APPNAME ="Babylon BTC Test"
BITCOIN_NETWORK =testnet
DEFINES   += BIP32_PUBKEY_VERSION=0x043587CF

else ifeq ($(filter clean,$(MAKECMDGOALS)),)
$(error Unsupported COIN - use $(VARIANT_VALUES))
endif

APP_SOURCE_PATH += bitcoin_app_base/src src

# Application icons following guidelines:
# https://developers.ledger.com/docs/embedded-app/design-requirements/#device-icon
ICON_NANOX = icons/nanox_app_babylon.gif
ICON_NANOSP = icons/nanox_app_babylon.gif
ICON_STAX = icons/stax_app_babylon.gif
ICON_FLEX = icons/flex_app_babylon.gif

include bitcoin_app_base/Makefile

# Unit tests target
.PHONY: test
test:
	cd unit-tests && ./build.sh

.PHONY: test-coverage
test-coverage:
	cd unit-tests && ./build_coverage.sh

.PHONY: test-clean
test-clean:
	rm -rf unit-tests/build unit-tests/build_coverage