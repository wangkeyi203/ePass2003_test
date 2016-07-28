
#include "pam_test.h"


#define	countof(a)			(sizeof(a)/ sizeof(CK_ATTRIBUTE))

char *g_strUserPIN;
CK_BBOOL bTrue = TRUE;
CK_ULONG ulModulusBits = MODULUS_BIT_LENGTH;  //MODULUS_BIT_LENGTH;
CK_BYTE subject[] = "Sample RSA Key Pair";
CK_ULONG keyType = CKK_RSA;


CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
CK_ATTRIBUTE pubTemplate[] = {
        {CKA_CLASS,		&pubClass,		sizeof(pubClass)},
        {CKA_KEY_TYPE,		&keyType,		sizeof(keyType)},
        {CKA_SUBJECT,		subject,		sizeof(subject)},
        {CKA_MODULUS_BITS,	&ulModulusBits, sizeof(ulModulusBits)},
        {CKA_ENCRYPT,		&bTrue,			sizeof(bTrue)},
        {CKA_TOKEN,		&bTrue,			sizeof(bTrue)},
        {CKA_WRAP,		&bTrue,			sizeof(bTrue)},
};	// Without specifying CKA_PRIVATE attribute in this case,
// a public key will be created by default.

CK_OBJECT_CLASS priClass	= CKO_PRIVATE_KEY;
CK_ATTRIBUTE priTemplate[] = {
        {CKA_CLASS,		&priClass,	sizeof(priClass)},
        {CKA_KEY_TYPE,		&keyType,	sizeof(keyType)},
        {CKA_SUBJECT,		subject,	sizeof(subject)},
        {CKA_DECRYPT,		&bTrue,		sizeof(bTrue)},
        {CKA_PRIVATE,		&bTrue,		sizeof(bTrue)},
        {CKA_SENSITIVE,		&bTrue,		sizeof(bTrue)},
        {CKA_TOKEN,		&bTrue,		sizeof(bTrue)},
        {CKA_EXTRACTABLE,	&bTrue,		sizeof(bTrue)},
        {CKA_UNWRAP,		&bTrue,		sizeof(bTrue)},
};

CK_MECHANISM keyGenMechanism = {
        CKM_RSA_PKCS_KEY_PAIR_GEN,
        NULL_PTR,
        0
};

CK_MECHANISM ckMechanism = {CKM_RSA_PKCS, NULL_PTR, 0};
 CK_BYTE pbMsg[] = "EnterSafe bring you into e-Business time.";
//CK_ULONG ulMsgLen = strlen((const char *)pbMsg);
CK_ULONG ulMsgLen =41;

CK_RV Connect()
{
    if(m_hSession) return CKR_OK;

    CK_RV rv;
    CK_ULONG ulCount = 0;
    rv = C_GetSlotList(TRUE, NULL_PTR, &ulCount);
    if(CKR_OK != rv )
    {
        printf("Can't Acquire information ,Error Code is 0x%08X", rv);
        return rv;
    }
    if(0 >= ulCount)
    {
        printf("\nCan't connect to Token ,Make sure you have inserted Token\n");
        return CKR_GENERAL_ERROR;
    }

    //m_pSlotList = (CK_SLOT_ID_PTR)new CK_SLOT_ID[ulCount];
    m_pSlotList = (CK_SLOT_ID_PTR)malloc(sizeof(CK_SLOT_ID)*ulCount);
    if (! m_pSlotList)
    {
        printf("\nCan't allocate enough memory\n");
        return CKR_HOST_MEMORY;

    }

    rv = C_GetSlotList(TRUE, m_pSlotList, &ulCount);
    if(CKR_OK != rv )
    {
        printf("Can't Acquire information ,Error Code is 0x%08X\n", rv);
        return rv;
    }
    if(0 >= ulCount)
    {
        printf("Can't connect to Token,Make sure you have inserted Token\n");
        return rv;
    }

    rv = C_OpenSession(
            m_pSlotList[0],  CKF_RW_SESSION | CKF_SERIAL_SESSION,
            &m_pApplication, NULL_PTR, &m_hSession);
    if(CKR_OK != rv )
    {
        printf("\nCan't Acquire information ,Error Code is 0x%08X\n", rv);
        //delete[] m_pSlotList;
        free(m_pSlotList);
        m_pSlotList = NULL_PTR;
        return rv;
    }
    else
    {
        printf("Success connect to Token\n");
        return rv;
    }
}

CK_RV Login()
{

    printf("You Must input user pin before generating RSA Key pair\n");
    char s[32];
    scanf("%s",s);
    g_strUserPIN = s;
    CK_ULONG ulPIN = strlen(g_strUserPIN);
    CK_BYTE_PTR pPIN = (CK_BYTE_PTR)g_strUserPIN;

    CK_RV rv;
    rv = C_Login(m_hSession, CKU_USER, pPIN, ulPIN);

    if(CKR_OK != rv)
    {
        printf("\nCan't use your pin login to Token ,Error code 0x%08X\n", rv);
        return rv;
    }
    else
    {
        printf("Success Login to Token\n");
        return rv;
    }
}