/**
*@file   DirtyFilterUtil.h
*@author alvinzhang
*@date   2021-01-11
*@brief
*
*       ���ֹ��˹�����
*/

#ifndef _DIRTYFILTER_UTIL_H_
#define _DIRTYFILTER_UTIL_H_

#include <stdio.h>
#include <string.h>
#include <iostream>
#include <algorithm>
#include <string>
#include <stdlib.h>
#include <time.h>
#include <sstream>
#include <sys/time.h>
using namespace std;

#include "CHConfigEx.h"
using namespace CHLib;

#define SO_CONF_PATH ("../config/so.conf")
#define DIRTYFILTER_IP CHCONF_PTR->GetString(SO_CONF_PATH, "dirtyfilter", "ip").c_str()
#define DIRTYFILTER_PORT CHCONF_PTR->GetInt(SO_CONF_PATH, "dirtyfilter", "port")
#define DIRTYFILTER_APPID CHCONF_PTR->GetString(SO_CONF_PATH, "dirtyfilter", "appid").c_str()
#define DIRTYFILTER_SECRET CHCONF_PTR->GetString(SO_CONF_PATH, "dirtyfilter", "secret").c_str()

class CDirtyFilterUtil
{
  public:		
    static string MakeDirtyFilterReq(unsigned int uiUin, int iZoneID, int iSceneID, const char* pszContent);
};

#endif//_DIRTYFILTER_UTIL_H_
