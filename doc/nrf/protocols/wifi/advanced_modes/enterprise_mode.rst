.. _ug_nrf70_developing_enterprise_mode:

Wi-Fi Enterprise test: X.509 Certificate header generation
**********************************************************

Wi-Fi enterprise security requires use of X.509 certificates, test certificates
in PEM format are committed to the repo at :zephyr_file:`subsys/net/lib/wifi_credentials/test_certs` and the during the
build process the certificates are converted to a C header file that is included by the Wi-Fi shell
module.

.. code-block:: bash

    $ cp client.pem subsys/net/lib/wifi_credentials/test_certs/
    $ cp client-key.pem subsys/net/lib/wifi_credentials/test_certs/
    $ cp ca.pem subsys/net/lib/wifi_credentials/test_certs/
    $ west build -p -b <board> samples/net/wifi -- -DEXTRA_CONF_FILE=overlay-enterprise.conf

To initiate Wi-Fi connection, the following command can be used:

.. code-block:: console

    uart:~$ wifi connect -s <SSID> -k 7 -a anon -K <key passphrase>

Server certificate is also provided in the same directory for testing purposes.
Any AAA server can be used for testing purposes, for example, ``FreeRADIUS`` or ``hostapd``.

.. note::

    The certificates are for testing purposes only and should not be used in production.
    They are generated using `FreeRADIUS raddb <https://github.com/FreeRADIUS/freeradius-server/tree/master/raddb/certs>`_ scripts.

API Reference
*************

.. doxygengroup:: wifi_mgmt
