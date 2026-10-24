/* Reconstructed C-like pseudocode; machine helpers preserve explicit widths/effects. */
uint64_t ura_opaque_even(uint64_t a0) {
    uint64_t in_rsp = ura_entry_rsp();
    uint64_t v15;
    uint32_t v110;
    uint32_t v119;
    uint32_t v124;
    uint32_t v143;
    uint32_t v174;
    uint32_t v183;
    uint32_t v193;
    uint32_t v214;
    uint64_t v230;

    L_140001000:
    v15 = ((uint64_t)((in_rsp) - (0x10ULL)));
    ura_store_u32(((uint64_t)((((uint64_t)((v15) + (0)))) + (8))), ((uint32_t)((((uint64_t)a0)) >> 0))); /* stack: local_8 */
    v110 = ura_load_u32(((uint64_t)((((uint64_t)((v15) + (0)))) + (8))));
    ura_store_u32(((uint64_t)((((uint64_t)((v15) + (0)))) + (4))), ((uint32_t)((((uint64_t)(v110))) >> 0))); /* stack: local_c */
    v119 = ura_load_u32(((uint64_t)((((uint64_t)((v15) + (0)))) + (4))));
    v124 = ura_load_u32(((uint64_t)((((uint64_t)((v15) + (0)))) + (4))));
    v143 = ((uint32_t)(((uint64_t)(((uint32_t)((((uint64_t)(v119))) >> 0)))) * ((uint64_t)(((uint32_t)((((uint64_t)(((uint32_t)((((uint32_t)((((uint64_t)(v124))) >> 0))) + (1)))))) >> 0))))));
    v174 = ((uint32_t)((((uint64_t)(((uint32_t)((((uint32_t)((((uint64_t)(v143))) >> 0))) & (1)))))) >> 0));
    if (((v174) == (0))) {
        v183 = ura_load_u32(((uint64_t)((((uint64_t)((v15) + (0)))) + (8))));
        v193 = ((uint32_t)((((uint32_t)((((uint64_t)(((uint32_t)((((uint32_t)((((uint64_t)(v183))) >> 0))) ^ (0x12345678ULL)))))) >> 0))) + (0x11ULL)));
        ura_store_u32(((uint64_t)((((uint64_t)((v15) + (0)))) + (0xcULL))), ((uint32_t)((((uint64_t)(v193))) >> 0))); /* stack: local_4 */
    } else {
        ura_store_u32(((uint64_t)((((uint64_t)((v15) + (0)))) + (0xcULL))), 0xfbad1234ULL); /* stack: local_4 */
    }
    v214 = ura_load_u32(((uint64_t)((((uint64_t)((v15) + (0)))) + (0xcULL))));
    v230 = ura_load_u64(((uint64_t)((v15) + (0x10ULL))));
    return ((uint64_t)(v214));
}
