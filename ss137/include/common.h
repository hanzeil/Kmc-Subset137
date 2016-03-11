/* ------------------------------------------------------------------------------- */
/* d e f i n e   c o n s t a n t s   a n d   m a c r o s                           */
/* ------------------------------------------------------------------------------- */
#include <libgen.h>

#ifdef __DEBUG__
#define debug_print(...) \
	do { fprintf(stdout, "DEBUG [%s: %d]\t", basename(__FILE__), __LINE__); fprintf(stdout, ##__VA_ARGS__); fflush(NULL); } while (0)
#else
#define debug_print(fmt, ...)
#endif					       

#define err_print(...) \
	do { fprintf(stderr, "ERR   [%s: %d]\t", basename(__FILE__), __LINE__); fprintf(stderr, ##__VA_ARGS__); fflush(NULL); } while (0)

#define warning_print(...) \
	do { fprintf(stderr, "WARN  [%s: %d]\t", basename(__FILE__), __LINE__); fprintf(stderr, ##__VA_ARGS__); fflush(NULL); } while (0)

/** Assert macro for defensive programming */
#define ASSERT(_condition, code)										\
	do {																\
		if ( !(_condition) )											\
		{																\
			err_print("Assertion failed code: %d\n", code);					\
			exit(code);													\
		}																\
	} while (0U)

/* ------------------------------------------------------------------------------- */
/* t y p e s                                                                       */
/* ------------------------------------------------------------------------------- */

typedef int32_t bool_t;

typedef enum
{
	E_NULL_POINTER     = 1,  /*     NULL pointer */
	E_BUFFER_TOO_SHORT = 2,
	E_INVALID_PARAM    = 3
} assert_error_code_t;

#ifndef FALSE
#define FALSE 0
#endif

#ifndef TRUE
#define TRUE 1
#endif
