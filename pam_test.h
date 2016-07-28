#ifndef __PAM_TEST_H
#define __PAM_TEST_H
#define MODULE_NAME "pam_my"
#define SAMPLE_PROMPT "Extra Password for root:"
#define PAM_DEBUG_ARG      1


//const CK_ULONG const MODULUS_BIT_LENGTH = 1024;

#include <security/pam_modules.h>
#include <security/pam_appl.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <syslog.h>
#include <stdlib.h>
#include "cryptoki_ext.h"



#define DPRINT if (ctrl & PAM_DEBUG_ARG) my_syslog

#define PAM_RET_CHECK(ret) if(PAM_SUCCESS != ret)  {return ret; }


int my_converse (pam_handle_t * pamh, int msg_style, char *message,char **password);
void my_pam_free (pam_handle_t * pamh, void *pbuf, int error_status);

//pkcs 封装



typedef int bool;
#define TRUE 1
#define FALSE 0

typedef struct CPKCSDemo
{

    void CPKCSDemo(void);
    ~CPKCSDemo();
    void ShowMsg(char *strInfo);
    void ShowErr(char *strInfo, CK_RV rv);
    void ClearMsg(void);
    CK_RV Connect();
    CK_RV Login();
    CK_RV Keypairgen();
    void Sign();
    void Verify();
    void Clearinfo();
    void Encrypt();
    void Decrypt();
    void Destroy();

    CK_SLOT_ID_PTR m_pSlotList;
    CK_VOID_PTR m_pApplication;
    CK_SESSION_HANDLE m_hSession;
    CK_OBJECT_HANDLE m_hPubKey;
    CK_OBJECT_HANDLE m_hPriKey;
    bool m_bKeyGen;
    CK_BYTE m_pSignature[1024];
    CK_BYTE_PTR m_pbCipherBuffer;
    CK_ULONG m_ulSignatureLen;
    CK_ULONG m_ulCipherLen;

};



#endif
