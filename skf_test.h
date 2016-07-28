#ifndef __SKF_TEST_H
#define __SKF_TEST_H




BOOL Test_ConnectDev(pam_handle_t *pamh,HANDLE *g_hDev);
BOOL Test_GetDevInfo_serialnu(HANDLE g_hDev, DEVINFO **devinfo);
BOOL Test_DevAuth(HANDLE g_hDev, HANDLE *m_hSessionKey);
BOOL Test_OpenApplication(HANDLE g_hDev, HANDLE *g_hApp);
BOOL Test_VerifyPIN(pam_handle_t *pamh,HANDLE g_hApp);

#endif
