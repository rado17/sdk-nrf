char *ca_cert = {
"-----BEGIN CERTIFICATE-----"
"MIIDhzCCAm+gAwIBAgIUVEIWtbeoz9hr6UwnoJ9iChSluh8wDQYJKoZIhvcNAQEL"
"BQAwUzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRIwEAYDVQQHDAlTb21ld2hl"
"cmUxEDAOBgNVBAoMB1NvbWVvbmUxETAPBgNVBAMMCEZvb2JhckNBMB4XDTI0MDUx"
"NTExMzIzOFoXDTI1MDUxNTExMzIzOFowUzELMAkGA1UEBhMCVVMxCzAJBgNVBAgM"
"AkNBMRIwEAYDVQQHDAlTb21ld2hlcmUxEDAOBgNVBAoMB1NvbWVvbmUxETAPBgNV"
"BAMMCEZvb2JhckNBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu7N4"
"QhrFrU3Y0bOi/vd14HlJS3sAy6aMuGV3RB09flriW7OhXQnc0ZNZyKBYmSymN4W+"
"kzQRLdi+0OJSo4dDmRunF1dE1rtxt7Jln480tHc697hHf3KtgCDUY8XCI9KVQOBE"
"/nqi/iLB/GvZmDzMsrkNa4nC4t5rj+fUFQVAZu99/4Bm+TKxGuLo1F4Ccc8N0lEn"
"psJW1F9O0/hyZTHQsm8po1U/IJrydmwgozAzZiBE4m+dGlmH2NaxDgjZlUfPGjJD"
"EnsiuzfChEEfm0zjCYk/DD8OsmAH5HUl6F4HCv+2Q6q8ODPsdBV/ASqyZ0+xChRz"
"pr7ZZakVvhAblxFvBwIDAQABo1MwUTAdBgNVHQ4EFgQUwNiV/9MmXAOcteWCW1Qn"
"QdIL6SUwHwYDVR0jBBgwFoAUwNiV/9MmXAOcteWCW1QnQdIL6SUwDwYDVR0TAQH/"
"BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAWNEFYNK++hrLayCJIMgZEAgHVp2N"
"UXSXgqGSqnrdCcvowWsxsyDkSZpmfeqmv6T1/mmvQTUfyv/oULiUfTfFSLSysg6d"
"Hbvlbou2wzV22VHpspCbASy5uSl4zT63pwuQEY8zDmV1BIxNERfJYBuPy00buupb"
"yU3of0v0JXmSn4T2WiLiF1VSdh4EkWoFd0hHT6mOKMSC6E48lLmRB23CnpRbsVF8"
"slYMC+oUJlT8Qbl+2LO8pNJEWZJTS0vSDNDxBxj3Uu53fqYRDIYYWWFSkcUhDUAF"
"o7gT4uoWLSnS08Az3ETB5SX3FyexrsP2kTnsVZIB4VNDL5tPSIf0P7SgQA=="
"-----END CERTIFICATE-----"
};

#if 0
unsigned char *ca_cert_encoded = {
    0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x42, 0x45, 0x47, 0x49, 0x4e, 0x20, 0x43,
  0x45, 0x52, 0x54, 0x49, 0x46, 0x49, 0x43, 0x41, 0x54, 0x45, 0x2d, 0x2d,
  0x2d, 0x2d, 0x2d, 0x0a, 0x4d, 0x49, 0x49, 0x44, 0x68, 0x7a, 0x43, 0x43,
  0x41, 0x6d, 0x2b, 0x67, 0x41, 0x77, 0x49, 0x42, 0x41, 0x67, 0x49, 0x55,
  0x56, 0x45, 0x49, 0x57, 0x74, 0x62, 0x65, 0x6f, 0x7a, 0x39, 0x68, 0x72,
  0x36, 0x55, 0x77, 0x6e, 0x6f, 0x4a, 0x39, 0x69, 0x43, 0x68, 0x53, 0x6c,
  0x75, 0x68, 0x38, 0x77, 0x44, 0x51, 0x59, 0x4a, 0x4b, 0x6f, 0x5a, 0x49,
  0x68, 0x76, 0x63, 0x4e, 0x41, 0x51, 0x45, 0x4c, 0x0a, 0x42, 0x51, 0x41,
  0x77, 0x55, 0x7a, 0x45, 0x4c, 0x4d, 0x41, 0x6b, 0x47, 0x41, 0x31, 0x55,
  0x45, 0x42, 0x68, 0x4d, 0x43, 0x56, 0x56, 0x4d, 0x78, 0x43, 0x7a, 0x41,
  0x4a, 0x42, 0x67, 0x4e, 0x56, 0x42, 0x41, 0x67, 0x4d, 0x41, 0x6b, 0x4e,
  0x42, 0x4d, 0x52, 0x49, 0x77, 0x45, 0x41, 0x59, 0x44, 0x56, 0x51, 0x51,
  0x48, 0x44, 0x41, 0x6c, 0x54, 0x62, 0x32, 0x31, 0x6c, 0x64, 0x32, 0x68,
  0x6c, 0x0a, 0x63, 0x6d, 0x55, 0x78, 0x45, 0x44, 0x41, 0x4f, 0x42, 0x67,
  0x4e, 0x56, 0x42, 0x41, 0x6f, 0x4d, 0x42, 0x31, 0x4e, 0x76, 0x62, 0x57,
  0x56, 0x76, 0x62, 0x6d, 0x55, 0x78, 0x45, 0x54, 0x41, 0x50, 0x42, 0x67,
  0x4e, 0x56, 0x42, 0x41, 0x4d, 0x4d, 0x43, 0x45, 0x5a, 0x76, 0x62, 0x32,
  0x4a, 0x68, 0x63, 0x6b, 0x4e, 0x42, 0x4d, 0x42, 0x34, 0x58, 0x44, 0x54,
  0x49, 0x30, 0x4d, 0x44, 0x55, 0x78, 0x0a, 0x4e, 0x54, 0x45, 0x78, 0x4d,
  0x7a, 0x49, 0x7a, 0x4f, 0x46, 0x6f, 0x58, 0x44, 0x54, 0x49, 0x31, 0x4d,
  0x44, 0x55, 0x78, 0x4e, 0x54, 0x45, 0x78, 0x4d, 0x7a, 0x49, 0x7a, 0x4f,
  0x46, 0x6f, 0x77, 0x55, 0x7a, 0x45, 0x4c, 0x4d, 0x41, 0x6b, 0x47, 0x41,
  0x31, 0x55, 0x45, 0x42, 0x68, 0x4d, 0x43, 0x56, 0x56, 0x4d, 0x78, 0x43,
  0x7a, 0x41, 0x4a, 0x42, 0x67, 0x4e, 0x56, 0x42, 0x41, 0x67, 0x4d, 0x0a,
  0x41, 0x6b, 0x4e, 0x42, 0x4d, 0x52, 0x49, 0x77, 0x45, 0x41, 0x59, 0x44,
  0x56, 0x51, 0x51, 0x48, 0x44, 0x41, 0x6c, 0x54, 0x62, 0x32, 0x31, 0x6c,
  0x64, 0x32, 0x68, 0x6c, 0x63, 0x6d, 0x55, 0x78, 0x45, 0x44, 0x41, 0x4f,
  0x42, 0x67, 0x4e, 0x56, 0x42, 0x41, 0x6f, 0x4d, 0x42, 0x31, 0x4e, 0x76,
  0x62, 0x57, 0x56, 0x76, 0x62, 0x6d, 0x55, 0x78, 0x45, 0x54, 0x41, 0x50,
  0x42, 0x67, 0x4e, 0x56, 0x0a, 0x42, 0x41, 0x4d, 0x4d, 0x43, 0x45, 0x5a,
  0x76, 0x62, 0x32, 0x4a, 0x68, 0x63, 0x6b, 0x4e, 0x42, 0x4d, 0x49, 0x49,
  0x42, 0x49, 0x6a, 0x41, 0x4e, 0x42, 0x67, 0x6b, 0x71, 0x68, 0x6b, 0x69,
  0x47, 0x39, 0x77, 0x30, 0x42, 0x41, 0x51, 0x45, 0x46, 0x41, 0x41, 0x4f,
  0x43, 0x41, 0x51, 0x38, 0x41, 0x4d, 0x49, 0x49, 0x42, 0x43, 0x67, 0x4b,
  0x43, 0x41, 0x51, 0x45, 0x41, 0x75, 0x37, 0x4e, 0x34, 0x0a, 0x51, 0x68,
  0x72, 0x46, 0x72, 0x55, 0x33, 0x59, 0x30, 0x62, 0x4f, 0x69, 0x2f, 0x76,
  0x64, 0x31, 0x34, 0x48, 0x6c, 0x4a, 0x53, 0x33, 0x73, 0x41, 0x79, 0x36,
  0x61, 0x4d, 0x75, 0x47, 0x56, 0x33, 0x52, 0x42, 0x30, 0x39, 0x66, 0x6c,
  0x72, 0x69, 0x57, 0x37, 0x4f, 0x68, 0x58, 0x51, 0x6e, 0x63, 0x30, 0x5a,
  0x4e, 0x5a, 0x79, 0x4b, 0x42, 0x59, 0x6d, 0x53, 0x79, 0x6d, 0x4e, 0x34,
  0x57, 0x2b, 0x0a, 0x6b, 0x7a, 0x51, 0x52, 0x4c, 0x64, 0x69, 0x2b, 0x30,
  0x4f, 0x4a, 0x53, 0x6f, 0x34, 0x64, 0x44, 0x6d, 0x52, 0x75, 0x6e, 0x46,
  0x31, 0x64, 0x45, 0x31, 0x72, 0x74, 0x78, 0x74, 0x37, 0x4a, 0x6c, 0x6e,
  0x34, 0x38, 0x30, 0x74, 0x48, 0x63, 0x36, 0x39, 0x37, 0x68, 0x48, 0x66,
  0x33, 0x4b, 0x74, 0x67, 0x43, 0x44, 0x55, 0x59, 0x38, 0x58, 0x43, 0x49,
  0x39, 0x4b, 0x56, 0x51, 0x4f, 0x42, 0x45, 0x0a, 0x2f, 0x6e, 0x71, 0x69,
  0x2f, 0x69, 0x4c, 0x42, 0x2f, 0x47, 0x76, 0x5a, 0x6d, 0x44, 0x7a, 0x4d,
  0x73, 0x72, 0x6b, 0x4e, 0x61, 0x34, 0x6e, 0x43, 0x34, 0x74, 0x35, 0x72,
  0x6a, 0x2b, 0x66, 0x55, 0x46, 0x51, 0x56, 0x41, 0x5a, 0x75, 0x39, 0x39,
  0x2f, 0x34, 0x42, 0x6d, 0x2b, 0x54, 0x4b, 0x78, 0x47, 0x75, 0x4c, 0x6f,
  0x31, 0x46, 0x34, 0x43, 0x63, 0x63, 0x38, 0x4e, 0x30, 0x6c, 0x45, 0x6e,
  0x0a, 0x70, 0x73, 0x4a, 0x57, 0x31, 0x46, 0x39, 0x4f, 0x30, 0x2f, 0x68,
  0x79, 0x5a, 0x54, 0x48, 0x51, 0x73, 0x6d, 0x38, 0x70, 0x6f, 0x31, 0x55,
  0x2f, 0x49, 0x4a, 0x72, 0x79, 0x64, 0x6d, 0x77, 0x67, 0x6f, 0x7a, 0x41,
  0x7a, 0x5a, 0x69, 0x42, 0x45, 0x34, 0x6d, 0x2b, 0x64, 0x47, 0x6c, 0x6d,
  0x48, 0x32, 0x4e, 0x61, 0x78, 0x44, 0x67, 0x6a, 0x5a, 0x6c, 0x55, 0x66,
  0x50, 0x47, 0x6a, 0x4a, 0x44, 0x0a, 0x45, 0x6e, 0x73, 0x69, 0x75, 0x7a,
  0x66, 0x43, 0x68, 0x45, 0x45, 0x66, 0x6d, 0x30, 0x7a, 0x6a, 0x43, 0x59,
  0x6b, 0x2f, 0x44, 0x44, 0x38, 0x4f, 0x73, 0x6d, 0x41, 0x48, 0x35, 0x48,
  0x55, 0x6c, 0x36, 0x46, 0x34, 0x48, 0x43, 0x76, 0x2b, 0x32, 0x51, 0x36,
  0x71, 0x38, 0x4f, 0x44, 0x50, 0x73, 0x64, 0x42, 0x56, 0x2f, 0x41, 0x53,
  0x71, 0x79, 0x5a, 0x30, 0x2b, 0x78, 0x43, 0x68, 0x52, 0x7a, 0x0a, 0x70,
  0x72, 0x37, 0x5a, 0x5a, 0x61, 0x6b, 0x56, 0x76, 0x68, 0x41, 0x62, 0x6c,
  0x78, 0x46, 0x76, 0x42, 0x77, 0x49, 0x44, 0x41, 0x51, 0x41, 0x42, 0x6f,
  0x31, 0x4d, 0x77, 0x55, 0x54, 0x41, 0x64, 0x42, 0x67, 0x4e, 0x56, 0x48,
  0x51, 0x34, 0x45, 0x46, 0x67, 0x51, 0x55, 0x77, 0x4e, 0x69, 0x56, 0x2f,
  0x39, 0x4d, 0x6d, 0x58, 0x41, 0x4f, 0x63, 0x74, 0x65, 0x57, 0x43, 0x57,
  0x31, 0x51, 0x6e, 0x0a, 0x51, 0x64, 0x49, 0x4c, 0x36, 0x53, 0x55, 0x77,
  0x48, 0x77, 0x59, 0x44, 0x56, 0x52, 0x30, 0x6a, 0x42, 0x42, 0x67, 0x77,
  0x46, 0x6f, 0x41, 0x55, 0x77, 0x4e, 0x69, 0x56, 0x2f, 0x39, 0x4d, 0x6d,
  0x58, 0x41, 0x4f, 0x63, 0x74, 0x65, 0x57, 0x43, 0x57, 0x31, 0x51, 0x6e,
  0x51, 0x64, 0x49, 0x4c, 0x36, 0x53, 0x55, 0x77, 0x44, 0x77, 0x59, 0x44,
  0x56, 0x52, 0x30, 0x54, 0x41, 0x51, 0x48, 0x2f, 0x0a, 0x42, 0x41, 0x55,
  0x77, 0x41, 0x77, 0x45, 0x42, 0x2f, 0x7a, 0x41, 0x4e, 0x42, 0x67, 0x6b,
  0x71, 0x68, 0x6b, 0x69, 0x47, 0x39, 0x77, 0x30, 0x42, 0x41, 0x51, 0x73,
  0x46, 0x41, 0x41, 0x4f, 0x43, 0x41, 0x51, 0x45, 0x41, 0x57, 0x4e, 0x45,
  0x46, 0x59, 0x4e, 0x4b, 0x2b, 0x2b, 0x68, 0x72, 0x4c, 0x61, 0x79, 0x43,
  0x4a, 0x49, 0x4d, 0x67, 0x5a, 0x45, 0x41, 0x67, 0x48, 0x56, 0x70, 0x32,
  0x4e, 0x0a, 0x55, 0x58, 0x53, 0x58, 0x67, 0x71, 0x47, 0x53, 0x71, 0x6e,
  0x72, 0x64, 0x43, 0x63, 0x76, 0x6f, 0x77, 0x57, 0x73, 0x78, 0x73, 0x79,
  0x44, 0x6b, 0x53, 0x5a, 0x70, 0x6d, 0x66, 0x65, 0x71, 0x6d, 0x76, 0x36,
  0x54, 0x31, 0x2f, 0x6d, 0x6d, 0x76, 0x51, 0x54, 0x55, 0x66, 0x79, 0x76,
  0x2f, 0x6f, 0x55, 0x4c, 0x69, 0x55, 0x66, 0x54, 0x66, 0x46, 0x53, 0x4c,
  0x53, 0x79, 0x73, 0x67, 0x36, 0x64, 0x0a, 0x48, 0x62, 0x76, 0x6c, 0x62,
  0x6f, 0x75, 0x32, 0x77, 0x7a, 0x56, 0x32, 0x32, 0x56, 0x48, 0x70, 0x73,
  0x70, 0x43, 0x62, 0x41, 0x53, 0x79, 0x35, 0x75, 0x53, 0x6c, 0x34, 0x7a,
  0x54, 0x36, 0x33, 0x70, 0x77, 0x75, 0x51, 0x45, 0x59, 0x38, 0x7a, 0x44,
  0x6d, 0x56, 0x31, 0x42, 0x49, 0x78, 0x4e, 0x45, 0x52, 0x66, 0x4a, 0x59,
  0x42, 0x75, 0x50, 0x79, 0x30, 0x30, 0x62, 0x75, 0x75, 0x70, 0x62, 0x0a,
  0x79, 0x55, 0x33, 0x6f, 0x66, 0x30, 0x76, 0x30, 0x4a, 0x58, 0x6d, 0x53,
  0x6e, 0x34, 0x54, 0x32, 0x57, 0x69, 0x4c, 0x69, 0x46, 0x31, 0x56, 0x53,
  0x64, 0x68, 0x34, 0x45, 0x6b, 0x57, 0x6f, 0x46, 0x64, 0x30, 0x68, 0x48,
  0x54, 0x36, 0x6d, 0x4f, 0x4b, 0x4d, 0x53, 0x43, 0x36, 0x45, 0x34, 0x38,
  0x6c, 0x4c, 0x6d, 0x52, 0x42, 0x32, 0x33, 0x43, 0x6e, 0x70, 0x52, 0x62,
  0x73, 0x56, 0x46, 0x38, 0x0a, 0x73, 0x6c, 0x59, 0x4d, 0x43, 0x2b, 0x6f,
  0x55, 0x4a, 0x6c, 0x54, 0x38, 0x51, 0x62, 0x6c, 0x2b, 0x32, 0x4c, 0x4f,
  0x38, 0x70, 0x4e, 0x4a, 0x45, 0x57, 0x5a, 0x4a, 0x54, 0x53, 0x30, 0x76,
  0x53, 0x44, 0x4e, 0x44, 0x78, 0x42, 0x78, 0x6a, 0x33, 0x55, 0x75, 0x35,
  0x33, 0x66, 0x71, 0x59, 0x52, 0x44, 0x49, 0x59, 0x59, 0x57, 0x57, 0x46,
  0x53, 0x6b, 0x63, 0x55, 0x68, 0x44, 0x55, 0x41, 0x46, 0x0a, 0x6f, 0x37,
  0x67, 0x54, 0x34, 0x75, 0x6f, 0x57, 0x4c, 0x53, 0x6e, 0x53, 0x30, 0x38,
  0x41, 0x7a, 0x33, 0x45, 0x54, 0x42, 0x35, 0x53, 0x58, 0x33, 0x46, 0x79,
  0x65, 0x78, 0x72, 0x73, 0x50, 0x32, 0x6b, 0x54, 0x6e, 0x73, 0x56, 0x5a,
  0x49, 0x42, 0x34, 0x56, 0x4e, 0x44, 0x4c, 0x35, 0x74, 0x50, 0x53, 0x49,
  0x66, 0x30, 0x50, 0x37, 0x53, 0x67, 0x51, 0x41, 0x3d, 0x3d, 0x0a, 0x2d,
  0x2d, 0x2d, 0x2d, 0x2d, 0x45, 0x4e, 0x44, 0x20, 0x43, 0x45, 0x52, 0x54,
  0x49, 0x46, 0x49, 0x43, 0x41, 0x54, 0x45, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d,
  0x0a
}
#endif
char *ca_cert_blob = {
    "2d2d2d2d2d424547494e2043455254494649434154452d2d2d2d2d0a4d494944687a4343416d2b674177494241674955564549577462656f7a396872"
"3655776e6f4a39694368536c756838774451594a4b6f5a496876634e4151454c0a42514177557a454c4d416b474131554542684d4356564d78437a41"
"4a42674e564241674d416b4e424d524977454159445651514844416c546232316c6432686c0a636d55784544414f42674e5642416f4d42314e766257"
"5676626d55784554415042674e5642414d4d43455a7662324a68636b4e424d423458445449304d4455780a4e5445784d7a497a4f466f58445449314d"
"4455784e5445784d7a497a4f466f77557a454c4d416b474131554542684d4356564d78437a414a42674e564241674d0a416b4e424d52497745415944"
"5651514844416c546232316c6432686c636d55784544414f42674e5642416f4d42314e7662575676626d55784554415042674e560a42414d4d43455a"
"7662324a68636b4e424d494942496a414e42676b71686b6947397730424151454641414f43415138414d49494243674b434151454175374e340a5168"
"72467255335930624f692f76643134486c4a533373417936614d7547563352423039666c726957374f6858516e63305a4e5a794b42596d53796d4e34"
"572b0a6b7a51524c64692b304f4a536f3464446d52756e463164453172747874374a6c6e343830744863363937684866334b74674344555938584349"
"394b56514f42450a2f6e71692f694c422f47765a6d447a4d73726b4e61346e43347435726a2b6655465156415a7539392f34426d2b544b7847754c6f"
"314634436363384e306c456e0a70734a573146394f302f68795a544851736d38706f31552f494a7279646d77676f7a417a5a694245346d2b64476c6d"
"48324e617844676a5a6c556650476a4a440a456e7369757a6643684545666d307a6a43596b2f4444384f736d41483548556c3646344843762b325136"
"71384f4450736442562f415371795a302b784368527a0a7072375a5a616b56766841626c78467642774944415141426f314d775554416442674e5648"
"51344546675155774e69562f394d6d58414f63746557435731516e0a5164494c36535577487759445652306a42426777466f4155774e69562f394d6d"
"58414f63746557435731516e5164494c3653557744775944565230544151482f0a42415577417745422f7a414e42676b71686b694739773042415173"
"4641414f4341514541574e4546594e4b2b2b68724c6179434a494d675a454167485670324e0a5558535867714753716e72644363766f775773787379"
"446b535a706d6665716d763654312f6d6d765154556679762f6f554c695566546646534c5379736736640a4862766c626f7532777a56323256487073"
"7043624153793575536c347a543633707775514559387a446d56314249784e4552664a5942755079303062757570620a7955336f663076304a586d53"
"6e34543257694c6946315653646834456b576f466430684854366d4f4b4d5343364534386c4c6d52423233436e705262735646380a736c594d432b6f"
"554a6c543851626c2b324c4f38704e4a45575a4a5453307653444e447842786a33557535336671595244495959575746536b635568445541460a6f37"
"675434756f574c536e533038417a334554423553583346796578727350326b546e73565a494234564e444c357450534966305037536751413d3d0a2d"
"2d2d2d2d454e442043455254494649434154452d2d2d2d2d0a"
};

char *client_cert = {
"-----BEGIN CERTIFICATE-----"
"MIIDKzCCAhMCFFULlyn1qW40mplyq1OEbipIww4XMA0GCSqGSIb3DQEBCwUAMFMx"
"CzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDQTESMBAGA1UEBwwJU29tZXdoZXJlMRAw"
"DgYDVQQKDAdTb21lb25lMREwDwYDVQQDDAhGb29iYXJDQTAeFw0yNDA1MTUxMTMz"
"MThaFw0yNTA1MTUxMTMzMThaMFExCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDQTES"
"MBAGA1UEBwwJU29tZXdoZXJlMRAwDgYDVQQKDAdTb21lb25lMQ8wDQYDVQQDDAZG"
"b29iYXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCxUKXHzLahZOG2"
"abZQ1PQ+/nqisppN1nAB8IWyBBNf3WCGYckm/caMfRDeTlwJmPZZNDT9GPxaawiI"
"y+gRh9y5jJPgKwVWS0bJs/uLnnjl9iYeM4rCUyDBuXM5QZWQmmTIN/ULAALf8mjt"
"ksmSG16012bT0TQMor4MHXiLyVw8cdUZzJRvt7tmKLuJ8i/1rdO6gHWLbi5vGjok"
"ddrYy2Yn6Bw6MuSWaZ12euf7U+Cq3bXaMFJUEosvWE2BQ7fAINz0fqnJG8M5nTbn"
"62EpC0zkPQRyUgucke8GqpczP64QojJCOdsQfWBxGqzPays5IC5RH1rguBRoPbw5"
"7U/70PP7AgMBAAEwDQYJKoZIhvcNAQELBQADggEBAKTFhqe6+wwt4H9RApwZtIBr"
"E5+lKhdyshcJbD8J7+TY88rxBfpUiiUmKJEUAVHoMelY4nsh5imuehXNEqVizsxa"
"3oxVER5hbz23rMfUF9n1r7YF6naVLMTXpaZmgUP+7KkTSQZMWIsGOQMWwowXE7ti"
"XwHg2q/N34vFfy9gk7JWkEuKq9HVbD+yLmcJxyNKTflMuobG/Anco8V/Hup4AJwp"
"4BkUvmOVSYaFT0AH5PKhQXs2tOIEzh+3KsM8c9qpUsGENYGg+EVoHczL4t9gYu0s"
"CP/yQWuDbmHOStlgIPozBppvJQhbMpX235Nefj06MgEpxGxr+0L9ysknZqAruPQ="
"-----END CERTIFICATE-----"
};

char *client_cert_blob = {
    "2d2d2d2d2d424547494e2043455254494649434154452d2d2d2d2d0a4d4949444b7a434341684d434646554c6c796e31715734306d706c7971314f45"
"62697049777734584d413047435371475349623344514542437755414d464d780a437a414a42674e5642415954416c56544d51737743515944565151"
"4944414a44515445534d424147413155454277774a553239745a58646f5a584a6c4d5241770a446759445651514b444164546232316c6232356c4d52"
"45774477594456515144444168476232396959584a4451544165467730794e4441314d5455784d544d7a0a4d546861467730794e5441314d5455784d"
"544d7a4d5468614d464578437a414a42674e5642415954416c56544d517377435159445651514944414a44515445530a4d424147413155454277774a"
"553239745a58646f5a584a6c4d524177446759445651514b444164546232316c6232356c4d513877445159445651514444415a470a62323969595849"
"77676745694d4130474353714753496233445145424151554141344942447741776767454b416f494241514378554b58487a4c61685a4f47320a6162"
"5a513150512b2f6e71697370704e316e41423849577942424e663357434759636b6d2f63614d66524465546c774a6d505a5a4e445439475078616177"
"69490a792b6752683979356a4a50674b7756575330624a732f754c6e6e6a6c396959654d3472435579444275584d35515a57516d6d54494e2f554c41"
"414c66386d6a740a6b736d5347313630313262543054514d6f72344d4858694c795677386364555a7a4a52767437746d4b4c754a38692f3172644f36"
"6748574c62693576476a6f6b0a646472597932596e364277364d755357615a313265756637552b4371336258614d464a55456f737657453242513766"
"41494e7a3066716e4a47384d356e54626e0a3632457043307a6b50515279556775636b6538477170637a503634516f6a4a434f647351665742784771"
"7a506179733549433552483172677542526f506277350a37552f373050503741674d42414145774451594a4b6f5a496876634e4151454c4251414467"
"674542414b5446687165362b777774344839524170775a744942720a45352b6c4b6864797368634a6244384a372b545938387278426670556969556d"
"4b4a45554156486f4d656c59346e736835696d756568584e457156697a7378610a336f785645523568627a3233724d665546396e3172375946366e61"
"564c4d545870615a6d6755502b374b6b5453515a4d574973474f514d57776f7758453774690a5877486732712f4e33347646667939676b374a576b45"
"754b7139485662442b794c6d634a78794e4b54666c4d756f62472f416e636f38562f48757034414a77700a34426b55766d4f56535961465430414835"
"504b6851587332744f49457a682b334b734d3863397170557347454e5947672b45566f48637a4c34743967597530730a43502f7951577544626d484f"
"53746c6749506f7a427070764a5168624d70583233354e65666a30364d674570784778722b304c3979736b6e5a7141727550513d0a2d2d2d2d2d454e"
"442043455254494649434154452d2d2d2d2d0a"
};

char *private_key = {
"-----BEGIN RSA PRIVATE KEY-----"
"MIIEowIBAAKCAQEAsVClx8y2oWThtmm2UNT0Pv56orKaTdZwAfCFsgQTX91ghmHJ"
"Jv3GjH0Q3k5cCZj2WTQ0/Rj8WmsIiMvoEYfcuYyT4CsFVktGybP7i5545fYmHjOK"
"wlMgwblzOUGVkJpkyDf1CwAC3/Jo7ZLJkhtetNdm09E0DKK+DB14i8lcPHHVGcyU"
"b7e7Zii7ifIv9a3TuoB1i24ubxo6JHXa2MtmJ+gcOjLklmmddnrn+1Pgqt212jBS"
"VBKLL1hNgUO3wCDc9H6pyRvDOZ025+thKQtM5D0EclILnJHvBqqXMz+uEKIyQjnb"
"EH1gcRqsz2srOSAuUR9a4LgUaD28Oe1P+9Dz+wIDAQABAoIBAHJQ2FCz/pqW+54r"
"EUuTv9RNJKt4EltUgOn/M3LNheAsTWrV6GWm/zbb+uAYDOZzI3/nVLJIRYnVr67i"
"J0AGI5vMshm4Iry702t/ChG9nZxE0dZuzGr0RQ4gjdTAH7kWkRs0WFs7Kp9PHa7t"
"D9+OncRhiv3Mxo3O7k/JQEp/C2Q7vAYgU6cP8wGJm/P/LvWVIcJGODhvh8+yiLIn"
"OVvdjcwuqPSbAXFAM6oMtKK6w347a/wUijB7BI65dpQg8aReq1EtNSVfE+tV0lPu"
"UihvbP8NL7jg4zL9Ased7mSrSp/ckpFETGpIyLFrphICm90UuIhIJcP4MLmqzMbk"
"RIZoDsECgYEA5Ouekqw2EMsVIGdp9WaVN8dnL6UxRLR0rKC3ViKssZeG05v2OCjd"
"13+y2epYzDh2NEe0FbhEjA66GHldL6fj385IDrCduo2pDAU1igtIUeB00A9/28rQ"
"GanGK8dvaYY8clQuH8Ouw8bJwIjrNDnAra2O88YleagWdMTuQVDWRskCgYEAxkpE"
"PozVYz9RLfGttAXZhy7vt9zu2U1Uh++wlf8yWauRy9umbM7drxJuldZVnEG+9XIB"
"qfQDxNrIfYJ8nJDVF88uKGXA/SUrXbJnqwPeVXJhPDnPkaJ/IGRs2oBISVH1L2b2"
"u8TjDHmHJBRs1OZoK0Z4o7dXLLv2rAxp5B5J0qMCgYBORka1bk8aVOaHavTvJUF2"
"jic5QmnjTTTr5hRqTnbwTpiaeKSrNUYNrqtwGdJ9Gf1JCQ+JsbU2kr6NKcp0RhsD"
"5tv6seds541a/9j7t7nlzTMEBZi5hdK8Q7HwPERbN7wpd6FB2T5D0RAhVm/eLrU0"
"bbkIn8MmoxPyn3e8O7DZCQKBgQCJ/U7GlK0+1uZAacou2E9L0u8BbZ9N25Gy06t4"
"htJcMphQXHfRipgc6F/KqBCFn/8qwX7E7cndqT8SkMb1EZkpa4U8masWv1IRb0DT"
"cuq7XdCq37RCLen3+csCt3kWhRFyPl3/x4EVwlC4W/psojblvrHfhIwG1ntPuYfL"
"NwS6rwKBgCgznex27V4AQqYy/xE7yZlKCLGuL7xOfUosg3LUE81FMuXnbGIsd+n7"
"a0iWUJEIF3L9N5At08HLIX2WYVjI/L1JKJH4wE5/aUhecsAAef/DhK1roFuG91KN"
"tS0D4sDXrWnZhXOgzA0Uv0LFdeeY1nCUeUW0oLH0hNuyqJTxZWms"
"-----END RSA PRIVATE KEY-----"
};

char *private_key_blob = {
    "2d2d2d2d2d424547494e205253412050524956415445204b45592d2d2d2d2d0a4d4949456f77494241414b43415145417356436c783879326f575468"
"746d6d32554e5430507635366f724b6154645a77416643467367515458393167686d484a0a4a7633476a483051336b3563435a6a32575451302f526a"
"38576d7349694d766f455966637559795434437346566b744779625037693535343566596d486a4f4b0a776c4d6777626c7a4f5547566b4a706b7944"
"663143774143332f4a6f375a4c4a6b687465744e646d30394530444b4b2b4442313469386c6350484856476379550a623765375a6969376966497639"
"613354756f42316932347562786f364a485861324d746d4a2b67634f6a4c6b6c6d6d64646e726e2b31506771743231326a42530a56424b4c4c31684e"
"67554f337743446339483670795276444f5a3032352b74684b51744d35443045636c494c6e4a4876427171584d7a2b75454b4979516a6e620a454831"
"67635271737a3273724f53417555523961344c6755614432384f6531502b39447a2b77494441514142416f494241484a513246437a2f7071572b3534"
"720a455575547639524e4a4b7434456c7455674f6e2f4d334c4e68654173545772563647576d2f7a62622b754159444f5a7a49332f6e564c4a495259"
"6e56723637690a4a3041474935764d73686d34497279373032742f436847396e5a784530645a757a477230525134676a64544148376b576b52733057"
"4673374b703950486137740a44392b4f6e6352686976334d786f334f376b2f4a5145702f4332513776415967553663503877474a6d2f502f4c765756"
"49634a474f44687668382b79694c496e0a4f5676646a63777571505362415846414d366f4d744b4b3677333437612f7755696a423742493635647051"
"6738615265713145744e535666452b7456306c50750a556968766250384e4c376a67347a4c3941736564376d537253702f636b70464554477049794c"
"4672706849436d393055754968494a6350344d4c6d717a4d626b0a52495a6f4473454367594541354f75656b717732454d735649476470395761564e"
"38646e4c365578524c5230724b433356694b73735a6547303576324f436a640a31332b79326570597a4468324e456530466268456a41363647486c64"
"4c36666a3338354944724364756f32704441553169677449556542303041392f323872510a47616e474b38647661595938636c517548384f75773862"
"4a77496a724e446e417261324f3838596c65616757644d54755156445752736b4367594541786b70450a506f7a56597a39524c6647747441585a6879"
"377674397a7532553155682b2b776c663879576175527939756d624d376472784a756c645a566e45472b395849420a71665144784e724966594a386e"
"4a4456463838754b4758412f53557258624a6e7177506556584a6850446e506b614a2f49475273326f4249535648314c3262320a7538546a44486d48"
"4a425273314f5a6f4b305a346f3764584c4c7632724178703542354a30714d436759424f526b6131626b3861564f6148617654764a5546320a6a6963"
"35516d6e6a5454547235685271546e627754706961654b53724e55594e7271747747644a394766314a43512b4a736255326b72364e4b637030526873"
"440a3574763673656473353431612f396a3774376e6c7a544d45425a693568644b3851374877504552624e377770643646423254354430524168566d"
"2f654c7255300a62626b496e384d6d6f7850796e3365384f37445a43514b426751434a2f5537476c4b302b31755a4161636f753245394c3075384262"
"5a394e32354779303674340a68744a634d706851584866526970676336462f4b714243466e2f38717758374537636e64715438536b4d6231455a6b70"
"613455386d61735776314952623044540a6375713758644371333752434c656e332b63734374336b5768524679506c332f78344556776c4334572f70"
"736f6a626c7672486668497747316e74507559664c0a4e77533672774b426743677a6e65783237563441517159792f784537795a6c4b434c47754c37"
"784f66556f7367334c55453831464d75586e62474973642b6e370a61306957554a454946334c394e3541743038484c4958325759566a492f4c314a4b"
"4a48347745352f615568656373414165662f44684b31726f46754739314b4e0a745330443473445872576e5a68584f677a41305576304c4664656559"
"316e4355655557306f4c4830684e7579714a54785a576d730a2d2d2d2d2d454e44205253412050524956415445204b45592d2d2d2d2d0a"
};