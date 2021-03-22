#include <stdio.h>



#include <sys/socket.h>
#include <netinet/in.h>
union sockaddr_all {
    char sa_data[32];
    struct sockaddr sa; //16
    struct sockaddr_in si; //16
    struct sockaddr_in6 si6; //28
};



#include <ctype.h>
int sample_check_json(const char *value) {
	int ret = -1;
	int flg;
	int i, len;
	int ch;
	if (NULL == value || (len = strlen(value)) <= 1) {
		return (ret);
	}

	flg = -1;
	for (i = 0; i < len; i++) {
		ch = *(value + i);
		if (isspace(ch)) {
			continue;
		} else if ('[' == ch) {
			flg = 1;
		} else if ('{' == ch) {
			flg = 2;
		}
		break;
	}

	if (flg < 0) {
		return (ret);
	}

	for (i = len - 1; i > 0; i--) {
		ch = *(value + i);
		if (isspace(ch)) {
			continue;
		} else if (1 == flg && ']' == ch) {
			ret = 0;
		} else if (2 == flg && '}' == ch) {
			ret = 0;
		}
		break;
	}

	return (ret);
}




/**
* 去字符串尾部空格
*/

static inline void trim(char *buf)
{
	int i_tmp;

	if (NULL == buf || strnlen(buf, 4) <= 0) {
		return;
	}
	for (i_tmp = strlen(buf) - 1; i_tmp >= 0; i_tmp--) {
		if (isspace(buf[i_tmp])) {
			buf[i_tmp] = '\0';
		} else {
			break;
		}
	}
}

static inline void trim_space_char(char *buf, char c)
{
	int i;

	if (NULL == buf || strnlen(buf, 1) <= 0) {
		return;
	}
	for (i = strlen(buf) - 1; i >= 0; i--) {
		if (isspace(buf[i]) || c == buf[i]) {
			buf[i] = '\0';
		} else {
			break;
		}
	}
}


#if 0
#include <jni.h>
static inline char *get_jstring2char(JNIEnv *env, jstring j_str)
{
	if (env == NULL || NULL == (*env) || j_str == NULL) {
		return NULL;
	}
    return (char*)(*env)->GetStringUTFChars(env, j_str, NULL);
}
static inline jstring get_char2jstring(JNIEnv *env, char *sz_str)
{
    jstring j_ret = NULL;
	if (env == NULL || NULL == (*env) || sz_str == NULL) {
		return NULL;
	}
	j_ret = (*env)->NewStringUTF(env, sz_str);
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionClear(env);
    }
    return j_ret;
}

static inline int release_jstring_char(JNIEnv *env, jstring j_str, char *sz_str)
{
	if (env == NULL || NULL == (*env) || sz_str == NULL || NULL == j_str) {
		return (-1);
	}
	(*env)->ReleaseStringUTFChars(env, j_str, sz_str);
	return (0);
}
#endif
