/* ABI oracle: shared P4 OEM-client harness for Attach, PDN, PLMN, RRC.
 * Cross-compile with a specific WF830_* family. No stock code or binaries
 * are incorporated: all client entrypoints come from liblted.so at runtime.
 *
 * The launcher runs the guest with its working directory in a disposable
 * scratch folder, where each callback image is written for validation.
 */
extern int lted_client_init_ex(void *ctx, int identity);
extern int lted_client_deinit(void *ctx);
extern int LTED_AttachRequest(void *ctx, int device_id, const void *params);
extern int LTED_PDNConnRequest(void *ctx, int device_id, const void *params);
extern int LTED_RRCFunctionControlRequest(void *ctx, int device_id, const void *params);
extern int LTED_RRCFunctionControlGetRequest(void *ctx, int device_id, const void *params);
extern int LTED_RegisterCallbackResponse(void *ctx, int index, void *callback, void *user);
extern int printf(const char *, ...);
extern void *fopen(const char *, const char *);
extern unsigned int fwrite(const void *, unsigned int, unsigned int, void *);
extern int fclose(void *);
extern int usleep(unsigned int);
extern void exit(int);
static unsigned char ctx[512];
#if defined(WF830_PDN)
static unsigned char params[0x1a4];
#define FAMILY "PDN"
#define CALLBACK_INDEX 6
#define CALLBACK_LEN 0x2e6
#define CALLBACK_FILENAME "pdn-image.bin"
static int send_request(void) { return LTED_PDNConnRequest(ctx, 1, params); }
static void setup_request(void) {
    params[0] = 0x11; params[1] = 1;
    params[2] = 'i'; params[3] = 'm'; params[4] = 's';
    params[0x066] = 2; params[0x067] = 3; params[0x068] = 'u';
    params[0x0cc] = 'p';
    params[0x130] = 4; params[0x131] = 1;
    params[0x132] = 0x12; params[0x133] = 0x34;
    params[0x134] = 1; params[0x135] = 2;
    params[0x136] = 0xaa; params[0x137] = 0xbb;
    params[0x19a] = 1; params[0x19b] = 5;
    params[0x19c] = 0; params[0x19d] = 10;
    params[0x19e] = 0; params[0x19f] = 20;
    params[0x1a0] = 0; params[0x1a1] = 30;
    params[0x1a2] = 6; params[0x1a3] = 0xfe;
}
#elif defined(WF830_RRC)
static unsigned char params[5];
static unsigned char get_params[4];
#define FAMILY "RRC"
#define CALLBACK_INDEX 117
#define CALLBACK_LEN 6
#define CALLBACK_FILENAME "rrc-set-image.bin"
static int send_request(void) {
    int set_ret = LTED_RRCFunctionControlRequest(ctx, 1, params);
    printf("OEM_RRC_SET_REQUEST ret=%d\n", set_ret);
    int get_ret = LTED_RRCFunctionControlGetRequest(ctx, 1, get_params);
    printf("OEM_RRC_GET_REQUEST ret=%d\n", get_ret);
    return set_ret != 0 ? set_ret : get_ret;
}
static void setup_request(void) {
    params[0] = 0; params[1] = 7; params[2] = 0; params[3] = 1; params[4] = 1;
    get_params[0] = 0; get_params[1] = 7; get_params[2] = 0; get_params[3] = 0;
}
#elif defined(WF830_PLMN)
static unsigned char params[9];
#define FAMILY "PLMN"
#define CALLBACK_INDEX 9
#define CALLBACK_LEN 436
#define CALLBACK_FILENAME "plmn-image.bin"
extern int LTED_PLMNSearchRequest(void *ctx, int device_id, const void *params);
static int send_request(void) { return LTED_PLMNSearchRequest(ctx, 1, params); }
static void setup_request(void) {
    params[0] = 1; params[1] = 2; params[2] = 6;
    params[3] = 0; params[4] = 0; params[5] = 1; params[6] = 0x0f;
    params[7] = 3; params[8] = 4;
}
#else
static unsigned char params[352];
#define FAMILY "ATTACH"
#define CALLBACK_INDEX 2
#define CALLBACK_LEN 0x88b
#define CALLBACK_FILENAME "attach-image.bin"
static int send_request(void) { return LTED_AttachRequest(ctx, 1, params); }
static void setup_request(void) {
    params[0] = 1; params[1] = 7;
    params[2] = 'i'; params[3] = 'n'; params[4] = 't'; params[5] = 'e';
    params[6] = 'r'; params[7] = 'n'; params[8] = 'e'; params[9] = 't';
    params[0x066] = 3; params[0x067] = 1; params[0x068] = 'u';
    params[0x0a8] = 'p';
    params[0x0e8] = 2; params[0x0e9] = 1;
    params[0x0ea] = 0x12; params[0x0eb] = 0x34;
    params[0x0ec] = 1; params[0x0ed] = 2;
    params[0x0ee] = 0xaa; params[0x0ef] = 0xbb;
    params[0x152] = 0; params[0x153] = 4; params[0x154] = 5;
    params[0x155] = 0; params[0x156] = 1;
    params[0x157] = 0; params[0x158] = 1;
    params[0x159] = 0; params[0x15a] = 20;
    params[0x15b] = 1; params[0x15c] = 44;
    params[0x15d] = 0; params[0x15e] = 10;
    params[0x15f] = 1;
}
#endif
static volatile int callback_count;
static void on_response(void *device, void *data, void *user, void *other) {
    callback_count++;
    printf("OEM_%s_CB count=%d device=%p image=%p user=%p other=%p\n",
           FAMILY, callback_count, device, data, user, other);
    if (data) {
        void *out = fopen(CALLBACK_FILENAME, "wb");
        if (out) {
            unsigned int n = fwrite(data, 1, CALLBACK_LEN, out);
            fclose(out);
            printf("OEM_%s_IMAGE_BYTES=%u\n", FAMILY, n);
        }
    }
}
#if defined(WF830_RRC)
static void on_rrc_get(void *device, void *data, void *user, void *other) {
    callback_count++;
    printf("OEM_RRC_GET_CB count=%d device=%p image=%p user=%p other=%p\n",
           callback_count, device, data, user, other);
    if (data) {
        void *out = fopen("rrc-get-image.bin", "wb");
        if (out) {
            unsigned int n = fwrite(data, 1, 7, out);
            fclose(out);
            printf("OEM_RRC_GET_IMAGE_BYTES=%u\n", n);
        }
    }
}
#endif
static int app(void) {
    setup_request();
    int result = lted_client_init_ex(ctx, 0);
    printf("OEM_INIT ret=%d\n", result);
    if (result < 0) return 10;
    result = LTED_RegisterCallbackResponse(ctx, CALLBACK_INDEX, (void *)on_response, 0);
    printf("OEM_REGISTER_%s ret=%d\n", FAMILY, result);
#if defined(WF830_RRC)
    int second = LTED_RegisterCallbackResponse(ctx, 118, (void *)on_rrc_get, 0);
    printf("OEM_REGISTER_RRC_GET ret=%d\n", second);
#endif
    result = send_request();
    printf("OEM_%s_REQUEST ret=%d\n", FAMILY, result);
    usleep(1000000);
    printf("OEM_%s_CALLBACK_COUNT=%d\n", FAMILY, callback_count);
    result = lted_client_deinit(ctx);
    printf("OEM_DEINIT ret=%d\n", result);
    return 0;
}
__attribute__((noreturn)) void _start(void) {
    exit(app());
    __builtin_unreachable();
}
