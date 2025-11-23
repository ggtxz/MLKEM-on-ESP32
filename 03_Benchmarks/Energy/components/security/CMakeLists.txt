idf_component_register(SRCS "encryption.c" "hash.c"
                       INCLUDE_DIRS "includes"
                       PRIV_INCLUDE_DIRS "../kem_kyber_512/includes"
                       PRIV_INCLUDE_DIRS "../comm/includes"
                       REQUIRES mbedtls kem_kyber_512 comm)
