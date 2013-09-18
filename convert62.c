#include <stdio.h>
#include <math.h>
#include <string.h>
#include <sys/time.h>
#include "global.h"
#include "md5.h"

#define WORD_LENGTH 4

#define MD_CTX MD5_CTX
#define MDInit MD5Init
#define MDUpdate MD5Update
#define MDFinal MD5Final

static unsigned char char_set[63] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
static unsigned char word[WORD_LENGTH];

static void ConvertTo62(long value, int length)
{
    memset(word, 0, WORD_LENGTH);
    if (value < 62) {
        word[WORD_LENGTH - 1] = char_set[value];
        return;
    } else {
        long result = value;
        //char[] ch = new char[length];
        int i = WORD_LENGTH - 1;
        while (i >= 0 &&result > 0)
        {
            long val = result % 62;
            //ch[--length] = charSet[val];
            word[i] = char_set[val];
            result /= 62;
            i--;
        }
    }
}

int main()
{
    int minLength = 1;
    int maxLength = WORD_LENGTH;

    int word_count = 0;

    struct timeval endTime, startTime;
    double timedif;
    MD_CTX context;
    /* Start timer */
    gettimeofday(&startTime, NULL);

    for (int i = minLength; i <= maxLength; i++) {
        long maxNum = (long)pow(62, i);

        #pragma omp parallel for num_threads(2)
        for (long j = 0; j < maxNum; j++) {
            ConvertTo62(j, i);
            //printf("%s\n", word);
            unsigned char digest[16];
            MDInit (&context);
            MDUpdate(&context, word, i);
            MDFinal(digest, &context);

            #pragma omp critical (section1)
            {
                word_count++;
            }
        }
    }

    /* Stop timer */
    gettimeofday(&endTime, NULL);

    printf(" Word_count: %d\n", word_count);
    printf(" Done\n");

    timedif = (endTime.tv_sec - startTime.tv_sec) + (endTime.tv_usec - startTime.tv_usec) / 1000000.0;
    printf("\n Time = %f seconds\n", timedif);

    return 0;
}
