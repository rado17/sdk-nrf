.. _ug_nrf70_wifi_advanced_security_modes:

Wi-Fi Enterprise test: X.509 Certificate header generation
**********************************************************

Wi-Fi enterprise security requires use of X.509 certificates, test certificates
in PEM format are committed to the repo at :zephyr_file:`samples/net/wifi/test_certs/` and the during the
build process the certificates are converted to a C header file that is included by the Wi-Fi shell
module.

.. code-block:: bash

    $ cp client.pem samples/net/wifi/test_certs/
    $ cp client-key.pem samples/net/wifi/test_certs/
    $ cp ca.pem samples/net/wifi/test_certs/
    $ cp client.pem samples/net/wifi/test_certs/client2.pem
    $ cp client-key.pem samples/net/wifi/test_certs/client-key2.pem
    $ cp ca.pem samples/net/wifi/test_certs/ca2.pem
    $ west build -p -b <board> samples/net/wifi -- -DEXTRA_CONF_FILE=overlay-enterprise.conf

.. note::
     The certificates mentioned here are copied under sdk-zephyr repository for testing purposes. Same certificates are used in the sample application.
     may be copied to other samples or applications for testing purposes.
     The second set of certificates (suffixed with 2) are included here to avoid build time errors. These
     certificates are not used in the sample application.

To initiate Wi-Fi connection, the following command can be used:

.. code-block:: console

    uart:~$ wifi connect -s <SSID> -k 7 -a anon -K <key passphrase>

Server certificate is also provided in the same directory for testing purposes.
Any AAA server can be used for testing purposes, for example, ``FreeRADIUS`` or ``hostapd``.

.. note::

    The certificates are for testing purposes only and should not be used in production.
    They are generated using `FreeRADIUS raddb <https://github.com/FreeRADIUS/freeradius-server/tree/master/raddb/certs>`_ scripts.


Wi-Fi PSA support
#################

.. contents::
   :local:
   :depth: 2

The nRF70 Series devices support the Platform Security Architecture(PSA) security framework.
This is achieved by providing PSA API support for Wi-Fi cryptographic operations.

.. _ug_nrf70_developing_enabling_psa_support:

Enabling Wi-Fi PSA support
**************************

To enable the Wi-Fi PSA support in your applications, use the :kconfig:option:`CONFIG_WIFI_NM_WPA_SUPPLICANT_CRYPTO_ALT_NCS_PSA` Kconfig option.

.. _ug_nrf70_developing_current_psa_support:

Current Wi-Fi PSA Support level
*******************************

The nRF70 Series devices currently support Wi-Fi Protected Access (WPA2™) and open security profiles.
WPA2 security profiles use PSA APIs for cryptographic operations during connection establishment.
WPA3 and Enterprise security profiles are currently disabled for PSA operation and will not function when the :kconfig:option:`CONFIG_WIFI_NM_WPA_SUPPLICANT_CRYPTO_ALT_NCS_PSA` Kconfig option is enabled.

.. _ug_nrf70_developing_connection_establishment:

Connection establishement for WPA2 using PSA
********************************************

To establish a Wi-Fi connection with a WPA2 security profile, run the following command:

.. code-block:: console

   uart:~$ wifi connect -s <SSID> -p <passphrase> -k 1

