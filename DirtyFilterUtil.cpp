#include "DirtyFilterUtil.h"
#include "algo_hmac.h"

#include "error/en.h"
#include "writer.h"
#include "document.h"     // rapidjson's DOM-style API
#include "stringbuffer.h"
using namespace rapidjson;


typedef  unsigned short     uint16_t;
typedef unsigned int        uint32_t;

static const unsigned char BASE64_ENC_MAP[64] =
{
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',
    'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
    'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd',
    'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
    'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x',
    'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', '+', '/'
};

int base64_encode(const unsigned char *in,
        size_t in_len,
        unsigned char *out,
        size_t *out_len)
{
    size_t i, leven;
    unsigned char *p;
    size_t output_len = 4 * ((in_len + 2) / 3);

    if (*out_len < output_len + 1)
    {
        *out_len = output_len + 1;
        return -1;
    }

    p = out;
    leven = 3 * (in_len / 3);

    for (i = 0; i < leven; i += 3)
    {
        *p++ = BASE64_ENC_MAP[(in[0] >> 2) & 0x3F];
        *p++ = BASE64_ENC_MAP[(((in[0] & 3) << 4) + (in[1] >> 4)) & 0x3F];
        *p++ = BASE64_ENC_MAP[(((in[1] & 0xf) << 2) + (in[2] >> 6)) & 0x3F];
        *p++ = BASE64_ENC_MAP[in[2] & 0x3F];
        in += 3;
    }

    if (i < in_len)
    {
        unsigned a = in[0];
        unsigned b = (i + 1 < in_len) ? in[1] : 0;
        *p++ = BASE64_ENC_MAP[(a >> 2) & 0x3F];
        *p++ = BASE64_ENC_MAP[(((a & 3) << 4) + (b >> 4)) & 0x3F];
        *p++ = (i + 1 < in_len) ? BASE64_ENC_MAP[(((b & 0xf) << 2)) & 0x3F] : '=';
        *p++ = '=';
    }

    *p = '\0';
    *out_len = output_len;
    return 0;
}


int hex_to_str(const unsigned char *buf, size_t buf_len,
        char *dest, size_t dest_len, bool upper_case = true)
{
    if (dest_len < buf_len * 2 + 1)
    {
        return -1;
    }

    uint16_t *p_dest = (uint16_t *)dest;

    for (unsigned int i = 0; i < buf_len; ++ i)
    {
        *p_dest = single_hex_to_str(buf[i], upper_case);
        p_dest++;
    }

    *(char *)p_dest = 0;
    return 0;

}

void int_2_string(uint32_t uin, std::string &openid)
{
    std::stringstream ss;
    ss << uin;
    openid = ss.str();
}

std::string get_cur_usec_str()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm *cur_time;
    cur_time = localtime(&tv.tv_sec);
    char temp[30] = { 0 };
    snprintf(temp, sizeof(temp), "%04d%02d%02d%02d%02d%02d%03ld%03ld", cur_time->tm_year + 1900, \
            cur_time->tm_mon + 1, cur_time->tm_mday, cur_time->tm_hour, cur_time->tm_min, cur_time->tm_sec, \
            tv.tv_usec / 1000, tv.tv_usec % 1000);
    return (std::string)temp;
}

int get_signature(string& password)
{	
	uint32_t rand_num = rand();

	string random;
	int_2_string(rand_num, random);

    const char* key = DIRTYFILTER_SECRET;

	string appid_str = DIRTYFILTER_APPID;    
	string cur_time = get_cur_usec_str();

	string data = appid_str + '&' + random + '&' +  cur_time ;

	unsigned char * mac = NULL;
	unsigned int mac_length = 0;

	// gen hmac str
	int ret = HmacEncode("sha256", key, strlen(key), data.c_str(), data.length(), mac, mac_length);	
	if(0 != ret)
	{
		cout << "Algorithm HMAC encode failed!" << endl;
		return -1;
	}

	char hmac_str[256];
	hex_to_str(mac, mac_length, hmac_str, 256);	
	
	std::string base64_str_in;
	base64_str_in = data + '.' + hmac_str;

	char base64_str_out[1024] = {0};
	size_t base64_out_len = 1024;
	ret = base64_encode((const unsigned char *)base64_str_in.c_str(), base64_str_in.length(), (unsigned char *)base64_str_out, &base64_out_len);

    password = base64_str_out;

	if(mac) 
	{
		free(mac);
	}

    return 0;
}

string CDirtyFilterUtil::MakeDirtyFilterReq(unsigned int uiUin, int iZoneID, int iSceneID, const char* pszContent)
{
    StringBuffer sPostContent;
    Writer<StringBuffer> writer(sPostContent);		  

   	string strUin;
	int_2_string(uiUin, strUin);    

    string strSignature;
    get_signature(strSignature);

    int iAppID = CHCONF_PTR->GetInt(SO_CONF_PATH, "dirtyfilter", "appid");

    writer.StartObject();
        writer.Key("busi_head_");
        writer.StartObject();					
            writer.Key("authorization_");
            writer.String(strSignature.c_str());	
            writer.Key("app_id_");	
            writer.Int(iAppID);	
            writer.Key("service_name_");	
            writer.String("senstive_word");		
            writer.Key("scene_id_");	
            writer.Int(iSceneID);												
        writer.EndObject();        

        writer.Key("account_");
        writer.StartObject();					
            writer.Key("account_type_");
            writer.Int(1);	
            writer.Key("account_");	
            writer.String(strUin.c_str());	
            writer.Key("plat_id_");	
            writer.Int(2);		
            writer.Key("world_");	
            writer.Int(iZoneID);												
        writer.EndObject();
            
        writer.Key("busi_data_");
        writer.StartObject();
            writer.Key("pic_cnt_");	
            writer.Int(0);
            writer.Key("pic_list_");                        
            writer.StartArray();
                writer.StartObject();
                    writer.Key("pic_url_");
                    writer.String("");
                    writer.Key("pic_scene_");
                    writer.Int(0);                              
                writer.EndObject();	
            writer.EndArray();
            writer.Key("text_cnt_");	
            writer.Int(1);            
            writer.Key("text_list_");                        
            writer.StartArray();
                writer.StartObject();
                    writer.Key("text_code_");
                    writer.Int(1);
                    writer.Key("text_scene_");
                    writer.Int(0);
                    writer.Key("text_language_");
                    writer.Int(4);     
                    writer.Key("text_");
                    writer.String(pszContent);                                   
                writer.EndObject();	
            writer.EndArray();
        writer.EndObject();	     	
    writer.EndObject();	

    return sPostContent.GetString();
}



uint16_t testsingle_hex_to_str(unsigned char h, bool upper_case)
{

    static const char *tag_8_upper =
        "000102030405060708090A0B0C0D0E0F"
        "101112131415161718191A1B1C1D1E1F"
        "202122232425262728292A2B2C2D2E2F"
        "303132333435363738393A3B3C3D3E3F"
        "404142434445464748494A4B4C4D4E4F"
        "505152535455565758595A5B5C5D5E5F"
        "606162636465666768696A6B6C6D6E6F"
        "707172737475767778797A7B7C7D7E7F"
        "808182838485868788898A8B8C8D8E8F"
        "909192939495969798999A9B9C9D9E9F"
        "A0A1A2A3A4A5A6A7A8A9AAABACADAEAF"
        "B0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF"
        "C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF"
        "D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF"
        "E0E1E2E3E4E5E6E7E8E9EAEBECEDEEEF"
        "F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF";
    static const char *tag_8_lower =
        "000102030405060708090a0b0c0d0e0f"
        "101112131415161718191a1b1c1d1e1f"
        "202122232425262728292a2b2c2d2e2f"
        "303132333435363738393a3b3c3d3e3f"
        "404142434445464748494a4b4c4d4e4f"
        "505152535455565758595a5b5c5d5e5f"
        "606162636465666768696a6b6c6d6e6f"
        "707172737475767778797a7b7c7d7e7f"
        "808182838485868788898a8b8c8d8e8f"
        "909192939495969798999a9b9c9d9e9f"
        "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
        "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
        "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
        "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
        "e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
        "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
    static const char *tag_8 = upper_case ? tag_8_upper : tag_8_lower;
    uint16_t *p_src = (uint16_t *)tag_8;
    return p_src[h];
}