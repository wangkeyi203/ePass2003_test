#define PAM_SM_AUTH

#include "pam_test.h"

#define MODULE_NAME "pam_sample"
#define SAMPLE_PROMPT "Extra Password for root:"
#define PAM_DEBUG_ARG      1
#define _DEBUG
#ifdef _DEBUG
#define debug_printf(format, ...)	 printf(format, ##__VA_ARGS__)
#else
#define debug_printf(format, ...)
#endif

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
    char *puser, *ppwd, *get_usr, *token;
    int nret;
    int nloop;
    int nChallenge;
    int nValidrsp;
    char szbuf[256];
    char szconf[256];
    char *resp2challenge = NULL;
    char *ret_fgets = NULL;
    CK_ULONG i;
    CK_SLOT_ID_PTR pSlotList = NULL_PTR;
    FILE *fp;
    CK_RV rv;
    CK_ULONG ulCount = 0;
    CK_TOKEN_INFO  m_Info;

    char line[100] = {'\0'};
    int ctrl = 0;
    memset(szconf, 0, 256);
    //通过这个函数获得用户名  
    nret = pam_get_user(pamh, &puser, "UserName:");
    if(PAM_SUCCESS != nret)
    {
        int *pret = (int *)malloc(sizeof(int));
        DPRINT(LOG_DEBUG, "Get user name failed");
        *pret = nret;
        pam_set_data(pamh, "sample_setcred_return", (void *)pret, my_pam_free);
        return PAM_SYSTEM_ERR;
    }
    else
    {
        //打开配置文件
        debug_printf("%s\n",puser);
        debug_printf("get name  success\n");
        if((fp = fopen("/tmp/pam_test.conf", "r"))== NULL)
        {
            debug_printf("open error\n");
            return PAM_SYSTEM_ERR;
        }

        //cmp username

        while ((ret_fgets = fgets(line, 100, fp))!= NULL)
        {
            debug_printf("get success\n");
            debug_printf("\n%s\n",line);
            //int len = strlen(line);
            //line[len-1] = '\0';
            token = strtok(line, ":");
            debug_printf("name = %s\n", token);
            if (!strcasecmp (token, puser))
            {
                token = strtok(NULL, ":");//token is number
                debug_printf("get number = %s\n", token);
                break;
            }

        }

        //can't find name
        if(ret_fgets == NULL)
        {
            int *pret = (int *) malloc (sizeof (int));
            DPRINT (LOG_DEBUG, "Get  file info failed");
            *pret = 1;
            pam_set_data(pamh, "my_setcred_return", (void *)pret, my_pam_free);
            fclose(fp);
            return PAM_SYSTEM_ERR;
        }

        //get key number
        rv = C_Initialize(NULL_PTR); //初始化PKCS库

        if(CKR_OK != rv)
        {
            printf("Can not load PKCS#11 lib\n");
            C_Finalize(NULL_PTR);
            return PAM_AUTH_ERR;
        }

        rv = C_GetSlotList(TRUE, NULL_PTR, &ulCount);
        if(ulCount <= 0)
        {
            printf("Please insert usbkey\n");
            C_Finalize(NULL_PTR);
            return PAM_AUTH_ERR;
        }

        pSlotList = (CK_SLOT_ID_PTR)malloc(ulCount * sizeof(CK_SLOT_ID));
        if (! pSlotList)
        {
            C_Finalize(NULL_PTR);
            return PAM_AUTH_ERR;
        }

        rv = C_GetSlotList(TRUE, pSlotList, &ulCount);
        //cmp number

        for(i = 0; i < ulCount; i++)
        {
            debug_printf("%d\n",i);
            debug_printf("\nGet the serial number of the %d Token", i + 1);
            rv = C_GetTokenInfo(pSlotList[i], &m_Info);
            CK_BYTE sn[17];
            sn[16] = 0;

            memcpy(sn, m_Info.serialNumber, 16);
            debug_printf("\nusb Serial number = %s\n", sn);
            debug_printf("usbconf number = %s\n",token);
            debug_printf("%d\n",i);
            debug_printf("%d\n",strcasecmp(sn,token));
            if (!strcasecmp(sn,token))
            {

                break;
            }
            debug_printf("---------------------\n");

        }
        debug_printf("\n\n1111111   %d     %d\n",i,ulCount);
        if (ulCount == (i+1))
        {
            C_Finalize(NULL_PTR);
            return PAM_AUTH_ERR ;
        }
        debug_printf("111111111111111\n");


        m_pApplication = (char *)malloc(sizeof(char)*255);
        memset(m_pApplication, 0, 255);
        strcpy((char*)m_pApplication, "PKCS Demo App");
        m_hSession = NULL_PTR;
        m_hPubKey = NULL_PTR;
        m_hPriKey = NULL_PTR;

        memset(m_pSignature, 0, MODULUS_BIT_LENGTH);
        m_ulSignatureLen = sizeof(m_pSignature);
        m_pbCipherBuffer = NULL_PTR;
        m_ulCipherLen = 0;

        rv = Connect(pSlotList[0]);
        if(CKR_OK != rv)
        {
            C_Finalize(NULL_PTR);
            return PAM_AUTH_ERR;
        }
        rv = Login();
        if(CKR_OK != rv)
        {
            C_Finalize(NULL_PTR);
            return PAM_AUTH_ERR;
        }
        /*
        if(!strcasecmp("root", puser))
        {
            //用户是root 验证usbkey



            m_pApplication = (char *)malloc(sizeof(char)*255);
            memset(m_pApplication, 0, 255);
            strcpy((char*)m_pApplication, "PKCS Demo App");
            m_hSession = NULL_PTR;
            m_hPubKey = NULL_PTR;
            m_hPriKey = NULL_PTR;

            memset(m_pSignature, 0, MODULUS_BIT_LENGTH);
            m_ulSignatureLen = sizeof(m_pSignature);
            m_pbCipherBuffer = NULL_PTR;
            m_ulCipherLen = 0;


            rv = Connect();
            if(CKR_OK != rv)
            {
                C_Finalize(NULL_PTR);
                return FALSE;
            }
            rv = Login();
            if(CKR_OK != rv)
            {
                C_Finalize(NULL_PTR);
                return FALSE;
            }
            */




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

            */

        }
    fclose(fp);
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