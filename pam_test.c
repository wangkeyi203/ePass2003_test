#define PAM_SM_AUTH

#include "pam_test.h"

#define MODULE_NAME "pam_sample"
#define SAMPLE_PROMPT "Extra Password for root:"
#define PAM_DEBUG_ARG      1

#define DPRINT if (ctrl & PAM_DEBUG_ARG) sample_syslog

#define PAM_RET_CHECK(ret) if(PAM_SUCCESS != ret) \
                               {                        \  
                                    return ret;         \  
                               }



//if debug is setting this function can write log information /var/log/message
static void sample_syslog(int err, const char *format, ...)
{
    va_list args;
    char buffer[1024];

    va_start(args, format);
    vsprintf(buffer, format, args);
    /* don't do openlog or closelog, but put our name in to be friendly */
    syslog(err, "%s: %s", MODULE_NAME, buffer);
    va_end(args);
}

//get the paramters
static int sample_parse(int argc, const char **argv, char *szconf)
{
    int ctrl=0;

    /*
     *  If either is not there, then we can't parse anything.
     */
    if ((argc == 0) || (argv == NULL)) {
        return ctrl;
    }

    /* step through arguments */
    for (ctrl=0; argc-- > 0; ++argv)
    {

        /* generic options */
        if (!strcmp(*argv, "debug"))
        {
            ctrl |= PAM_DEBUG_ARG;
        }
        else
        {
            sample_syslog(LOG_WARNING, "unrecognized option '%s'", *argv);
        }
    }
    return ctrl;
}

//callback function to release a buffer
void my_pam_free(pam_handle_t *pamh, void *pbuf, int error_status)
{
    free(pbuf);
}


//conversation function
//这个是做了封装的对话函数,每次只允许你向应用程序请求一个"问题"
int my_converse(pam_handle_t *pamh, int msg_style, char *message, char **password)
{
    const struct pam_conv *conv;

    struct pam_message resp_message;
    const struct pam_message *msg[1];
    struct pam_response *resp = NULL;

    int retval;

    resp_message.msg_style = msg_style;
    resp_message.msg = message;
    msg[0] = &resp_message;
    //之前老提到对话函数,我们说过对话函数由应用程序提供,这里可以看到在模块中怎么获得对话函数
    //通过pam_get_item 可以获得pam_conv这个结构的一个指针(第二个参数是PAM_CONV表示类型)  
    //然后就想下面的调用方式,你可以在你的模块中调用这个对话函数,和应用程序交互  
    retval = pam_get_item(pamh, PAM_CONV, (const void **)&conv);
    PAM_RET_CHECK(retval)

    retval = conv->conv(1, msg, &resp, conv->appdata_ptr);
    PAM_RET_CHECK(retval)
    if(password)
    {
        *password = resp->resp;
        free(resp);
    }

    return PAM_SUCCESS;
}



#ifdef PAM_SM_AUTH
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    char *puser, *ppwd;
    int nret;
    int nloop;
    int nChallenge;
    int nValidrsp;
    char szbuf[256];
    char szconf[256];
    char *resp2challenge = NULL;

    CK_RV rv;

    int ctrl = 0;
    memset(szconf, 0, 256);
    //通过这个函数获得用户名  
    nret = pam_get_user(pamh, &puser, "UserName:");
    if(PAM_SUCCESS != nret)
    {
        int *pret = (int *)malloc(sizeof(int));
        //makelog("get username failed");
        DPRINT(LOG_DEBUG, "Get user name failed");
        *pret = nret;
        pam_set_data(pamh, "sample_setcred_return", (void *)pret, my_pam_free);
        return PAM_SYSTEM_ERR;
    }
    else
    {
        //username
        //如果用户名为root,请用户输入附加密码 "123456"

        if(!strcasecmp("root", puser))
        {
            //用户是root 验证usbkey
            rv = C_Initialize(NULL_PTR); //初始化PKCS库

            if(CKR_OK != rv)
            {
                printf("Can not load PKCS#11 lib\n");

                C_Finalize(NULL_PTR);
                return FALSE;
            }

            struct CPKCSDemo demo;
            rv = demo.Connect();
            if(CKR_OK != rv)
            {
                C_Finalize(NULL_PTR);
                return FALSE;
            }
            rv = demo.Login();
            if(CKR_OK != rv)
            {
                C_Finalize(NULL_PTR);
                return FALSE;
            }




            //usbkey 验证通过,让用户输入密码
           /*
            nret = my_converse(pamh, PAM_PROMPT_ECHO_OFF, SAMPLE_PROMPT, &ppwd);
            if(PAM_SUCCESS != nret)
            {
                int *pret = (int *)malloc(sizeof(int));
                *pret = nret;
                DPRINT(LOG_DEBUG, "Get extra password failed");
                pam_set_data(pamh, "sample_setcred_return", (void *)pret, my_pam_free);
                return nret;
            }
            //you have get the extra password
            if(strcasecmp("123456", ppwd))
            {
                int *pret = (int *)malloc(sizeof(int));
                *pret = PAM_AUTH_ERR;
                DPRINT(LOG_DEBUG, "Invalid extra password");
                pam_set_data(pamh, "sample_setcred_return", (void *)pret, my_pam_free);
                return PAM_AUTH_ERR;
            }
            */
        }
    }
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    int nret = PAM_SUCCESS, *pret;
    pret = &nret;
    pam_get_data(pamh, "sample_setcred_return", (void **)&pret);
    return *pret;
}

#endif//PAM_SM_AUTH