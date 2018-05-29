package decipher;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.concurrent.ThreadLocalRandom;
import lombok.Data;

/**
 * <p>Uses cryptanalysis to decipher text encrypted using the Subsition Cipher.
 * See <a href="https://en.wikipedia.org/wiki/Substitution_cipher">Subsition cipher wiki</a></p>
 * 
 * <p>First creates</p>
 */
public class SubstitutionCipher {
	/** The number of different letters in cipher text */
	int numOfDiffCharsInCText;
	
    /** The first 100 common words in English (removing any less than 3 charters like: a, an) */
    static List<String> COMMON_WORDS = Arrays.asList("the","and","that","have","for","not","with","you","this","but","his", "from", "they", 
                  "say", "her", "she", "will", "one", "all", "would", "there", "their", "what", "out", "about", "who", "get", "which", "when", 
                  "make", "can", "like", "time", "just", "him", "know", "take", "people", "into", "year", "your", "good", "some", "could", 
                  "them", "see", "other", "than", "then", "now", "look", "only", "come", "its", "over", "think", "also", "back", "after", 
                  "use", "two", "how", "our", "work", "first", "well", "way", "even", "new", "want", "because", "any", "these", "give", 
                  "day", "most");

    /**
    * Returns the a count of common words of at lease 3 charters, found in the text string.
    * @param text a string of potently English words
    * @return the count of words found
    */
    int wordCount(String text) {
           int rtnCount = 0;
           for (String aWord: COMMON_WORDS) {
        	   rtnCount += text.split(aWord, -1).length-1;
           }
           return rtnCount;
    }

    /** Ordering of the alphabet according to the letter's use in English */
    short[] STAND_ORDER = {4, 19, 0, 14, 18, 13, 8, 7, 17, 11, 3, 22, 20, 12, 6, 5, 2, 24, 15, 1, 25, 23, 21, 16, 10, 9 }; 
    //                     e  t   a  o   s   n   i  h  r   l   d  w   u   m   g  f  c  y   p   b  z   x   v   q   k   j

    /**
     * <p>This class is used to store one of 26 letters and the count of use in the cipher text.
     * And then order by count (Comparable) and match that ordering to 
     * the standard use in English (STAND_ORDER) * to create the fist mapping.</p>
     *
     * <p><strong>For example:</strong> etaosnihrldwumgfcypbzxvqkj is standard frequency order of
     * use in English 'e' being used most and 'j' used least.
     * After getting all the counts from the cipher text and sorting,
     * if 'n' is used the most in the cipher text then we map 'n' to 'e'. The next most used
     * char to 't' and so on.</p>
     */
    @Data  // lombok.Data is used to create getters
	class AlphCount implements Comparable<AlphCount> {
    	/** This object's letter */
		private Character letter;
		/** Count of this letter in the cipher text. */
		private int count = 0;
		/** Constructor: taking the letter for this object*/
		public AlphCount(Character letter) {
			super();
			this.letter = letter;
		}
		/** Adds one to the current count */
		public void plussOne() {
			count++;
		}
		/** Used to sort AlphCount's in frequency/count order. */
		@Override
		public int compareTo(AlphCount otherAlphCount) {
			return count - otherAlphCount.count;
		}
		@Override
		public boolean equals(Object o) {
		    return count == ((AlphCount) o).count;
		}
		@Override
		public int hashCode() {
		    return java.util.Objects.hash(count, letter);
		}
	}

	/**
	 * Creates a map based on frequency analysis of the cipher text.
	 * Map the most frequent letter to the most frequent letter in English e and so on.
	 * 
	 * @param cipherText the cipher text to analyze. 
	 * @return a simple array for mapping of letters
	 */
    public short[] frequencyAnalysis(String cipherText) {
    	// Create map to each letter
        HashMap<Character, AlphCount> alphMap = new HashMap<>();
        for (int i = 0; i < 26; i++) {
            char currLet = (char)('a' + i);
            alphMap.put(currLet, new AlphCount(currLet));
        }

        // first count the frequency of letters in the cipher text:
        AlphCount anAlphCount;
        for (char currLet : cipherText.toCharArray()) {
        	if((anAlphCount = alphMap.get(currLet)) != null)
        		anAlphCount.plussOne();
        }

        // Now make a list of the values
        List<AlphCount> aList = new ArrayList<>();
        aList.addAll(alphMap.values());
        
        // create frequency list in most frequent order
        Collections.sort(aList);
        Collections.reverse(aList);
        
        // create initial mapping
        int soIndex = 0;  // STAND_ORDER index
        short[] rtnMap = new short[26];
        // Go though the alphCount in most frequent to lest frequent order
        // and assign to the next standard English order character.
        for (AlphCount alphCount : aList) {
            rtnMap[alphCount.getLetter()-'a'] = STAND_ORDER[soIndex++];
        }
        return rtnMap;
    }

    /**
     * Finds the letter in the map and returns the index of where it is in the map.
     * @param letter the letter to find in this map
     * @param map the map
     * @return the position in the map
     */
    short indexof(short letter, short[] map) {
    	for (short i = 0; i < 26; i++) {
    		if(letter == map[i])
    			return i;
    	}
    	return -1;
    }

    /**
     * Print this map in standard frequency order (e,t,a,o...)
     * @param map the map to print
     */
    void printMap(short[] map) {
    	StringBuilder prtStr = new StringBuilder();
    	int j;
    	for (int i = 0; i < 26; i++) {
    		j = indexof(STAND_ORDER[i],map); 
    		prtStr.append((char)('a'+j)).append('-').append((char)('a'+map[j])).append(',');
		}
    	System.out.printf("map is %s\n", prtStr.toString());
    }


    /**
     * Substitutes the letters with other letters according to the map.
     * Note: that this can decipher and encipher text 
     * @param text the text to use substitute letters in
     * @param map the map of letters to substitute
     * @return a substituted text
     */
    String subsitute(String text, short[] map) {
        StringBuffer rtnStr = new StringBuffer();
        for(byte aChar : text.getBytes()) {
        	if(aChar < 'a' || aChar > 'z') {
        		rtnStr.append((char)aChar);
        	} else {
        		rtnStr.append((char)('a'+map[aChar-'a']));
        	}
        }
        return rtnStr.toString();
    }

    /**
     * Deciphers cipher text that was enciphered using the substitution cipher.
     * <ol>
     *    <li>Using single letter frequency analysis creates the first mapping</li>
     *    <li>Improves the first mapping with bubble sort (n passes)</li>
     *    <li></li>
     *    <li>Randomly select two points on the map to swop and check if it improves the resulting deciphered text</li>
     * </ol>
     * to score changes in the map to find the best mapping and decipher the cipher text.
     * @throws Exception
     */
    void decipherSubstitutionCipher(String cipherText) throws Exception {
    	// load NGram files
        NGram quadGram = new NGram("quadgrams.txt");
        NGram biGram = new NGram("bigrams.txt");

        // create variables outside of the loop
        long startTime = System.nanoTime(); // used for measure the time taken
        short[] firstMap = frequencyAnalysis(cipherText);
        printMap(firstMap);
        String bestStr = subsitute(cipherText, firstMap);
        double bestScore = quadGram.score(bestStr);
        int bestWordCount = 0;
        String str;
        double aScore;
        int numNoChange = 0;
        short temp;
        int i,j,thisWordCount;
        int numDoOvers=0;
        double bestBiScore=biGram.score(bestStr);

        // first do a bubble sort through the map to improve the firstMap before the random swooping:
        for (int pass = 0; pass < 10; pass++) {  // three passes
        	for (int index = 0; index < 25; index++) {
        		// swaps 2 position next to each other in standered order
        		// starting at the high freq side and moving down (bubble sort style).
        		i = indexof(STAND_ORDER[index],firstMap);
        		j = indexof(STAND_ORDER[index+1],firstMap);

        		// swap them
        		temp = firstMap[j];
        		firstMap[j] = firstMap[i];
        		firstMap[i] = temp;

        		// decipher with this new mapping
        		str = subsitute(cipherText, firstMap);
        		aScore = biGram.score(str);
        		if(aScore > bestBiScore) {
        		    // if better, replace best variables
        			bestStr = str;
        			bestScore = quadGram.score(bestStr);
        			bestBiScore = aScore;
        		}else{
        			// if not as good, put them back
        			temp = firstMap[j];
        			firstMap[j] = firstMap[i];
        			firstMap[i] = temp;
        		}
			}
		}

        /********************************************************
         * This number of words to get from the cipher text.
         * Too high and it will run forever.
         * Too low and it will not make sense.
         ********************************************************/
        int numWordsTarget = cipherText.length()/14;
        short[] bestMap = Arrays.copyOf(firstMap, 26);
        ThreadLocalRandom currentRandon = ThreadLocalRandom.current();
        while(numNoChange<10000 && numDoOvers < 1000) {
        	// if bestWordCount is still less than numWordsTarget words and 
        	// the number of iterations without change is close-to-the-limit of tries
        	// start back from the firstMap
        	if(numNoChange>9990 && bestWordCount < numWordsTarget) {
        		System.out.printf("doOver->%.50s<-,%d<%d\n",bestStr,bestWordCount,numWordsTarget);
        		printMap(bestMap);
        		// lets start back from the original mapping
        		bestMap = Arrays.copyOf(firstMap, 26);
        		bestStr = subsitute(cipherText, bestMap);
        		bestScore = quadGram.score(bestStr);
        		bestWordCount=wordCount(bestStr);
        		numNoChange = 0;
        		++numDoOvers;
        	}

        	// randomly swap two charter mappings
        	i = currentRandon.nextInt(0, 26);
        	j = currentRandon.nextInt(0, 26);
        	while(i==j)
        		j = currentRandon.nextInt(0, 26);

        	// swap
        	temp = bestMap[j];
        	bestMap[j] = bestMap[i];
        	bestMap[i] = temp;

        	str = subsitute(cipherText, bestMap);
        	thisWordCount = wordCount(str);

        	if(thisWordCount>bestWordCount) {
        		// System.out.printf("%2d->%.30s<-\n",thisWordCount,str);
        		bestWordCount=thisWordCount;
        	}
        	aScore = quadGram.score(str);
        	if(aScore > bestScore) {
        		bestStr = str;
        		bestScore = aScore;
        		numNoChange = 0;
        	}else{
        		// put them back
        		temp = bestMap[j];
        		bestMap[j] = bestMap[i];
        		bestMap[i] = temp;
        		numNoChange++;
        	}
        }
        long endtime = System.nanoTime();
        System.out.printf("Time taken: %f seconds\n",((double)(endtime-startTime))/1000000000.0);
        System.out.printf("bestWordCount->%d<-\n",bestWordCount);
        System.out.printf("->%s<-\n",bestStr);
        printMap(bestMap);
    }

    /**
     * Used to test the SubstitutionCipher class
     * @param args not used
     */
    public static void main(String[] args) {
        try {
        	SubstitutionCipher aSubstitutionCipher = new SubstitutionCipher();
        	aSubstitutionCipher.decipherSubstitutionCipher("qbufujyyxrccpqbnmrjsceqduuqnmrqbukfuonpumqchqbuemnqupoqjquonoqbuhccpqbuxkeqxcenmqbnoynqqyufccdanqbveoqjsceqjmxqbnmrxcepajmqqcujqcfpfnmtseqonmlumedsufcmunajomqbemrfxseqqbnfoqxjmpmedsufqacqbuxajohfuundeoqbjgupfjmtdujsceqhnhquumpfkukkufo");
//        	aSubstitutionCipher.decipherSubstitutionCipher("dgcizeejntczdgwlzizeejnejuctczdgizqkclaccdwnaczqlacswdwqdgcznnwsrzdwucwnacziicvdwdzljqcjndgcmsczdcdcsqzenjsrljnewnczqtdszqlnjsrzdwjq");
//        	aSubstitutionCipher.decipherSubstitutionCipher("wgegijzzbifzunuruaizmrgtgxdglmxmozewafobazunzwlbleiondglmxmozewaumzwzuwxonnifzomnoqzacoifaczziezaaabzujubbmgqoepsfzzmoepcgmwacfonzifzomzumasuefzumifzyuewcfonzifzomfzumiasuerzifmonnzwuewyuwzfubbozmifzjoewgxifoepadglyzueigaudcfzeifzdumzpgezaudrzxgmzifzdpg");
//        	aSubstitutionCipher.decipherSubstitutionCipher("ltkhnmevkgkecvhvrtmheccvknbkncvhwxtfmcxhagfrknkcenxcexqhcvknbyxpfhrtnknezvxxfopcklyxpvrihncfhrtnhmcvhqhrnknbxlltkhnmevkgyxpthrffyvrihncfhrtnhmrnycvknbqpvrqqrmrfk");

//        	String cText = "ufhlfxhthkhyfirjrtfhtixmfertushlfpfmhxfrtjwrth,rtuwffrxwuwjftugmo,ruftufmfiuwfmfhdysbqsfumohkstfsbuwfqsdrufhygkfyftukuwfbrbufftuwjftugmokhevhqhtfttsldfrurtushmfdrxrstsbhfkuwfurjrkyufhrkyufhrkyrkhjgdubsgtifistuwfhismhurstsbuwflfhgurbgdhystxuwfksmiribhjuksbfpfmoihofcrkuftjfrurtjgdjhufkqgmruohtiwhmysto,uwfyokufmosbygughdjwhmruo,uwfmsyhturjrkysbuwfksjrhdsmifmrurkfkkfturhddohesmkwrqsbuwfryqfmbfju,hkrurkhuftifmhuufyquushjjsyqdrkwksyfuwrtxqskkrldfrtuwrkryqskkrldfuwrtxefatsehkdrbfuwfqwrdsksqwosbufhrktsuyfmfhfkuwfurjrkyrtuwfsmirthmohjjfquhtjfsbuwfufmy,bsmrufcqmfkkfkjstvsrtudoeruwfuwrjkhtimfdrxrstsgmewsdfqsrtusbprfehlsguyhthtithugmfrurkwoxrftf,bsmruftbsmjfkjdfhtdrtfkk;rurkfjstsyrjk,bsmrukwsekjsybsmurtkryqdrjruomhuwfmuwhtrtuwfjsyqdfchtijskudo;rurkysmhdxfsyfumo,rthkygjwhkruifbrtfksgmkftkfsbqmsqsmurstusuwfgtrpfmkfrumfqmfkftukuwfumgfkqrmrusbfhkufmtifysjmhjoloyhartxhddrukpsuhmrfkhmrkusjmhukrtuhkufuwfdstxrksdhurstsbvhqhtbmsyuwfmfkusbuwfesmdiksjstigjrpfusrtumskqfjurstwhklfftwrxwdobhpsgmhldfusuwfifpfdsqyftusbufhrkysgmwsyfhtiwhlrukjskugyfhtijgrkrtfqsmjfdhrtdhjzgfmqhrturtxsgmpfmodrufmhugmfhddwhpflfftkglvfjuusrukrtbdgftjf.tskugiftusbvhqhtfkfjgdugmfjsgdifpfmrxtsmfrukqmfkftjf.ruwhkqfmyfhufiuwffdfxhtjfsbtsldflsgisrmk,htiftufmfiuwfhlsifsbuwfwgyldf.sgmqfhkhtukwhpfdfhmtfiushmmhtxfbdsefmk,sgmyfhtfkudhlsgmfmussbbfmwrkkhdguhurstusuwfmsjakhtiehufmk.rtsgmjsyystqhmdhtjfefkqfhasbuwfyht\"eruwtsufh\"rtwry,ewftwfrkrtkgkjfqurldfusuwfkfmrs-jsyrjrtufmfkuksbuwfqfmksthdimhyh.hxhrtefkurxyhurkfuwfgtuhyfihfkuwfufews,mfxhmidfkksbuwfygtihtfumhxfio,mgtkmrsurtuwfkqmrtxurifsbfyhtjrqhufifysurstk,hkstf\"eruwussygjwufh\"rtwry.uwfsgukrifmyhortiffiestifmhuuwrkkffyrtxygjwhishlsgutsuwrtx.ewhuhufyqfkurthufh-jgq!wferddkho.lguewftefjstkrifmwsekyhddhbufmhdduwfjgqsbwgyhtftvsoyfturk,wseksstspfmbdsefieruwufhmk,wsefhkrdoimhrtfiusuwfimfxkrtsgmzgftjwdfkkuwrmkubsmrtbrtruo,efkwhddtsuldhyfsgmkfdpfkbsmyhartxksygjwsbuwfufh-jgq.yhtartiwhkistfesmkf.rtuwfesmkwrqsblhjjwgk,efwhpfkhjmrbrjfiussbmffdo;htiefwhpffpftumhtkbrxgmfiuwfxsmoryhxfsbyhmk.ewotsujstkfjmhufsgmkfdpfkusuwfzgfftsbuwfjhyfdrhk,htimfpfdrtuwfehmykumfhysbkoyqhuwouwhubdsekbmsywfmhduhm?rtuwfdrzgrihylfmeruwrtuwfrpsmo-qsmjfdhrt,uwfrtrurhufiyhousgjwuwfkeffumfurjftjfsbjstbgjrgk,uwfqrzghtjosbdhsukf,htiuwffuwfmfhdhmsyhsBKHAOHYGTRWRYKFDB.UWSKFEWSJHTTSUBFFDUWFDRUUDFTFKKSBXMFHUUWRTXKRTUWFYKFDPFKHMFHQUUSSPFMDSSAUWFXMFHUTFKKSBDRUUDFUWRTXKRTSUWFMK.UWFHPFMHXFEFKUFMTFM,RTWRKKDFFAJSYQDHJFTJO,ERDDKFFRTUWFUFHJFMFYSTOLGUHTSUWFMRTKUHTJFSBUWFUWSGKHTIHTISTFSIIRURFKEWRJWJSTKURUGUFUWFZGHRTUTFKKHTIJWRDIRKWTFKKSBUWFFHKUUSWRY.WFEHKESTUUSMFXHMIVHQHTHKLHMLHMSGKEWRDFKWFRTIGDXFIRTUWFXFTUDFHMUKSBQFHJF:WFJHDDKWFMJRPRDRKFIKRTJFKWFLFXHTUSJSYYRUEWSDFKHDFKDHGXWUFMSTYHTJWGMRHTLHUUDFBRFDIK.YGJWJSYYFTUWHKLFFTXRPFTDHUFDOUSUWFJSIFSBUWFKHYGMHR,--UWFHMUSBIFHUWEWRJWYHAFKSGMKSDIRFMKFCGDURTKFDB-KHJMRBRJF;LGUKJHMJFDOHTOHUUFTURSTWHKLFFTIMHETUSUFHRKY,EWRJWMFQMFKFTUKKSYGJWSBSGMHMUSBDRBF.BHRTESGDIEFMFYHRTLHMLHMRHTK,RBSGMJDHRYUSJRPRDRKHURSTEFMFUSLFLHKFISTUWFXMGFKSYFXDSMOSBEHM.BHRTESGDIEFHEHRUUWFURYFEWFTIGFMFKQFJUKWHDDLFQHRIUSSGMHMUHTIRIFHDK.EWFTERDDUWFEFKUGTIFMKUHTI,SMUMOUSGTIFMKUHTI,UWFFHKU?EFHKRHURJKHMFSBUFTHQQHDDFILOUWFJGMRSGKEFLSBBHJUKHTIBHTJRFKEWRJWWHKLFFTESPFTJSTJFMTRTXGK.EFHMFQRJUGMFIHKDRPRTXSTUWFQFMBGYFSBUWFDSUGK,RBTSUSTYRJFHTIJSJAMSHJWFK.RURKFRUWFMRYQSUFTUBHTHURJRKYSMFDKFHLVFJUPSDGQUGSGKTFKK.RTIRHTKQRMRUGHDRUOWHKLFFTIFMRIFIHKRXTSMHTJF,JWRTFKFKSLMRFUOHKKUGQRIRUO,VHQHTFKFQHUMRSURKYHKUWFMFKGDUSBBHUHDRKY.RUWHKLFFTKHRIUWHUEFHMFDFKKKFTKRLDFUSQHRTHTIESGTIKSTHJJSGTUSBUWFJHDDSGKTFKKSBSGMTFMPSGKSMXHTRKHURST!EWOTSUHYGKFOSGMKFDPFKHUSGMFCQFTKF?HKRHMFUGMTKUWFJSYQDRYFTU.UWFMFESGDILFBGMUWFMBSSIBSMYFMMRYFTURBOSGEFMFUSATSEHDDUWHUEFWHPFRYHXRTFIHTIEMRUUFTHLSGUOSG.HDDUWFXDHYSGMSBUWFQFMKQFJURPFRKUWFMF,HDDUWFGTJSTKJRSGKWSYHXFSBESTIFM,HDDUWFKRDFTUMFKFTUYFTUSBUWFTFEHTIGTIFBRTFI.OSGWHPFLFFTDSHIFIERUWPRMUGFKUSSMFBRTFIUSLFFTPRFI,HTIHJJGKFISBJMRYFKUSSQRJUGMFKZGFUSLFJSTIFYTFI.SGMEMRUFMKRTUWFQHKU--UWFERKFYFTEWSATFE--RTBSMYFIGKUWHUOSGWHILGKWOUHRDKKSYFEWFMFWRIIFTRTOSGMXHMYFTUK,HTISBUFTIRTFISBBHBMRJHKKFFSBTFELSMTLHLFK!THO,EFWHIKSYFUWRTXESMKFHXHRTKUOSG:EFGKFIUSUWRTAOSGUWFYSKURYQMHJURJHLDFQFSQDFSTUWFFHMUW,BSMOSGEFMFKHRIUSQMFHJWEWHUOSGTFPFMQMHJURJFI.KGJWYRKJSTJFQURSTKHMFBHKUPHTRKWRTXHYSTXKUGK.JSYYFMJFWHKBSMJFIUWFFGMSQFHTUSTXGFKSTYHTOHTFHKUFMTQSMU.HKRHURJOSGUWKHMFBDSJARTXUSEFKUFMTJSDDFXFKBSMUWFFZGRQYFTUSBYSIFMTFIGJHURST.SGMRTKRXWUISFKTSUQFTFUMHUFOSGMJGDUGMFIFFQDO,LGUHUDFHKUEFHMFERDDRTXUSDFHMT.KSYFSBYOJSYQHUMRSUKWHPFHISQUFIUSSYGJWSBOSGMJGKUSYKHTIUSSYGJWSBOSGMFURZGFUUF,RTUWFIFDGKRSTUWHUUWFHJZGRKRURSTSBKURBBJSDDHMKHTIUHDDKRDAWHUKJSYQMRKFIUWFHUUHRTYFTUSBOSGMJRPRDRKHURST.QHUWFURJHTIIFQDSMHLDFHKKGJWHBBFJUHURSTKHMF,UWFOFPRTJFSGMERDDRTXTFKKUSHQQMSHJWUWFEFKUSTSGMATFFK.GTBSMUGTHUFDOUWFEFKUFMTHUURUGIFRKGTBHPSGMHLDFUSUWFGTIFMKUHTIRTXSBUWFFHKU.UWFJWMRKURHTYRKKRSTHMOXSFKUSRYQHMU,LGUTSUUSMFJFRPF.OSGMRTBSMYHURSTRKLHKFISTUWFYFHXMFUMHTKDHURSTKSBSGMRYYFTKFDRUFMHUGMF,RBTSUSTUWFGTMFDRHLDFHTFJISUFKSBQHKKRTXUMHPFDDFMK.RURKMHMFDOUWHUUWFJWRPHDMSGKQFTSBHDHBJHIRSWFHMTSMUWHUSBUWFHGUWSMSB\"UWFEFLSBRTIRHTDRBF\"FTDRPFTKUWFSMRFTUHDIHMATFKKERUWUWFUSMJWSBSGMSETKFTURYFTUK.QFMWHQKRLFUMHOYOSETRXTSMHTJFSBUWFUFHJGDULOLFRTXKSSGUKQSAFT.RUKPFMOKQRMRUSBQSDRUFTFKKFCHJUKUWHUOSGKHOEWHUOSGHMFFCQFJUFIUSKHO,HTITSYSMF.LGURHYTSUUSLFHQSDRUFUFHRKU.KSYGJWWHMYWHKLFFTISTFHDMFHIOLOUWFYGUGHDYRKGTIFMKUHTIRTXSBUWFTFEESMDIHTIUWFSDI,UWHUSTFTFFITSUHQSDSXRKFBSMJSTUMRLGURTXWRKURUWFUSUWFBGMUWFMHTJFSBHLFUUFMGTIFMKUHTIRTX.UWFLFXRTTRTXSBUWFUEFTURFUWJFTUGMOESGDIWHPFLFFTKQHMFIUWFKQFJUHJDFSBKHTXGRTHMOEHMBHMFRBMGKKRHWHIJSTIFKJFTIFIUSATSEVHQHTLFUUFM.EWHUIRMFJSTKFZGFTJFKUSWGYHTRUODRFRTUWFJSTUFYQUGSGKRXTSMRTXSBFHKUFMTQMSLDFYK!FGMSQFHTRYQFMRHDRKY,EWRJWISFKTSUIRKIHRTUSMHRKFUWFHLKGMIJMOSBUWFOFDDSEQFMRD,BHRDKUSMFHDRKFUWHUHKRHYHOHDKSHEHAFTUSUWFJMGFDKFTKFSBUWFEWRUFIRKHKUFM.OSGYHODHGXWHUGKBSMWHPRTX\"USSYGJWUFH,\"LGUYHOEFTSUKGKQFJUUWHUOSGSBUWFEFKUWHPF\"TSUFH\"RTOSGMJSTKURUGURST?DFUGKKUSQUWFJSTURTFTUKBMSYWGMDRTXFQRXMHYKHUFHJWSUWFM,HTILFKHIIFMRBTSUERKFMLOUWFYGUGHDXHRTSBWHDBHWFYRKQWFMF.EFWHPFIFPFDSQFIHDSTXIRBBFMFTUDRTFK,LGUUWFMFRKTSMFHKSTEWOSTFKWSGDITSUKGQQDFYFTUUWFSUWFM.OSGWHPFXHRTFIFCQHTKRSTHUUWFJSKUSBMFKUDFKKTFKK;EFWHPFJMFHUFIHWHMYSTOEWRJWRKEFHAHXHRTKUHXXMFKKRST.ERDDOSGLFDRFPFRU?--UWFFHKURKLFUUFMSBBRTKSYFMFKQFJUKUWHTUWFEFKU!KUMHTXFDOFTSGXWWGYHTRUOWHKKSBHMYFURTUWFUFH-JGQ.RURKUWFSTDOHKRHURJJFMFYSTRHDEWRJWJSYYHTIKGTRPFMKHDFKUFFY.UWFEWRUFYHTWHKKJSBBFIHUSGMMFDRXRSTHTISGMYSMHDK,LGUWHKHJJFQUFIUWFLMSETLFPFMHXFERUWSGUWFKRUHURST.UWFHBUFMTSSTUFHRKTSEHTRYQSMUHTUBGTJURSTRTEFKUFMTKSJRFUO.RTUWFIFDRJHUFJDHUUFMSBUMHOKHTIKHGJFMK,RTUWFKSBUMGKUDFSBBFYRTRTFWSKQRUHDRUO,RTUWFJSYYSTJHUFJWRKYHLSGUJMFHYHTIKGXHM,EFATSEUWHUUWFESMKWRQSBUFHRKFKUHLDRKWFILFOSTIZGFKURST.UWFQWRDSKSQWRJMFKRXTHURSTSBUWFXGFKUUSUWFBHUFHEHRURTXWRYRTUWFIGLRSGKIFJSJURSTQMSJDHRYKUWHURTUWRKKRTXDFRTKUHTJFUWFSMRFTUHDKQRMRUMFRXTKKGQMFYF.UWFFHMDRFKUMFJSMISBUFHRTFGMSQFHTEMRURTXRKKHRIUSLFBSGTIRTUWFKUHUFYFTUSBHTHMHLRHTUMHPFDDFM,UWHUHBUFMUWFOFHM879UWFYHRTKSGMJFKSBMFPFTGFRTJHTUSTEFMFUWFIGURFKSTKHDUHTIUFH.YHMJSQSDSMFJSMIKUWFIFQSKRURSTSBHJWRTFKFYRTRKUFMSBBRTHTJFRT1285BSMWRKHMLRUMHMOHGXYFTUHURSTSBUWFUFH-UHCFK.RUEHKHUUWFQFMRSISBUWFXMFHUIRKJSPFMRFKUWHUUWFFGMSQFHTQFSQDFLFXHTUSATSEYSMFHLSGUUWFFCUMFYFSMRFTU.HUUWFFTISBUWFKRCUFFTUWJFTUGMOUWFWSDDHTIFMKLMSGXWUUWFTFEKUWHUHQDFHKHTUIMRTAEHKYHIFRTUWFFHKUBMSYUWFDFHPFKSBHLGKW.UWFUMHPFDDFMKXRSPHTTRLHURKUHMHYGKRS(1559),D.HDYFRIH(1576),YHBBFTS(1588),UHMFRMH(1610),HDKSYFTURSTFIUFH.RTUWFDHKU-THYFIOFHMKWRQKSBUWFIGUJWFHKURTIRHJSYQHTOLMSGXWUUWFBRMKUUFHRTUSFGMSQF.RUEHKATSETRTBMHTJFRT1636,HTIMFHJWFIMGKKRHRT1638.FTXDHTIEFDJSYFIRURT1650HTIKQSAFSBRUHK\"UWHUFCJFDDFTUHTILOHDDQWOKRJRHTKHQQMSPFIJWRTHIMRTA,JHDDFILOUWFJWRTFHTKUJWH,HTILOSUWFMTHURSTKUHO,HDRHKUFF.\"DRAFHDDXSSIUWRTXKSBUWFESMDI,UWFQMSQHXHTIHSBUFHYFUERUWSQQSKRURST.WFMFURJKDRAFWFTMOKHPRDDF(1678)IFTSGTJFIIMRTARTXRUHKHBRDUWOJGKUSY.VSTHKWHTEHO(FKKHOSTUFH,1756)KHRIUWHUYFTKFFYFIUSDSKFUWFRMKUHUGMFHTIJSYFDRTFKK,ESYFTUWFRMLFHGUOUWMSGXWUWFGKFSBUFH.RUKJSKUHUUWFKUHMU(HLSGUBRBUFFTSMKRCUFFTKWRDDRTXKHQSGTI)BSMLHIFQSQGDHMJSTKGYQURST,HTIYHIFRU\"MFXHDRHBSMWRXWUMFHUYFTUKHTIFTUFMUHRTYFTUK,QMFKFTUKLFRTXYHIFUWFMFSBUSQMRTJFKHTIXMHTIFFK.\"OFURTKQRUFSBKGJWIMHELHJAKUFH-IMRTARTXKQMFHIERUWYHMPFDSGKMHQRIRUO.UWFJSBBFF-WSGKFKSBDSTISTRTUWFFHMDOWHDBSBUWFFRXWUFFTUWJFTUGMOLFJHYF,RTBHJU,UFH-WSGKFK,UWFMFKSMUSBERUKDRAFHIIRKSTHTIKUFFDF,EWSLFXGRDFIUWFYKFDPFKSPFMUWFRM\"IRKWSBUFH.\"UWFLFPFMHXFKSSTLFJHYFHTFJFKKRUOSBDRBF--HUHCHLDFYHUUFM.EFHMFMFYRTIFIRTUWRKJSTTFJURSTEWHUHTRYQSMUHTUQHMURUQDHOKRTYSIFMTWRKUSMO.JSDSTRHDHYFMRJHMFKRXTFIWFMKFDBUSSQQMFKKRSTGTURDWGYHTFTIGMHTJFXHPFEHOLFBSMFUWFWFHPOIGURFKDHRISTUFH.HYFMRJHTRTIFQFTIFTJFIHUFKBMSYUWFUWMSERTXSBUFH-JWFKUKRTUSLSKUSTWHMLSGM.UWFMFRKHKGLUDFJWHMYRTUWFUHKUFSBUFHEWRJWYHAFKRURMMFKRKURLDFHTIJHQHLDFSBRIFHDRKHURST.EFKUFMTWGYSGMRKUKEFMFTSUKDSEUSYRTXDFUWFBMHXMHTJFSBUWFRMUWSGXWUERUWRUKHMSYH.RUWHKTSUUWFHMMSXHTJFSBERTF,UWFKFDB-JSTKJRSGKTFKKSBJSBBFF,TSMUWFKRYQFMRTXRTTSJFTJFSBJSJSH.HDMFHIORT1711,KHOKUWFKQFJUHUSM:\"RESGDIUWFMFBSMFRTHQHMURJGDHMYHTTFMMFJSYYFTIUWFKFYOKQFJGDHURSTKUSHDDEFDD-MFXGDHUFIBHYRDRFKUWHUKFUHQHMUHTWSGMFPFMOYSMTRTXBSMUFH,LMFHIHTILGUUFM;HTIESGDIFHMTFKUDOHIPRKFUWFYBSMUWFRMXSSIUSSMIFMUWRKQHQFMUSLFQGTJUGHDDOKFMPFIGQHTIUSLFDSSAFIGQSTHKHQHMUSBUWFUFH-FZGRQHXF.\"KHYGFDVSWTKSTIMHEKWRKSETQSMUMHRUHK\"HWHMIFTFIHTIKWHYFDFKKUFHIMRTAFM,EWSBSMUEFTUOOFHMKIRDGUFIWRKYFHDKERUWSTDOUWFRTBGKRSTSBUWFBHKJRTHURTXQDHTU;EWSERUWUFHHYGKFIUWFFPFTRTX,ERUWUFHKSDHJFIUWFYRITRXWU,HTIERUWUFHEFDJSYFIUWFYSMTRTX.\"JWHMDFKDHYL,HQMSBFKKFIIFPSUFF,KSGTIFIUWFUMGFTSUFSBUFHRKYEWFTWFEMSUFUWHUUWFXMFHUFKUQDFHKGMFWFATFEEHKUSISHXSSIHJURSTLOKUFHDUW,HTIUSWHPFRUBSGTISGULOHJJRIFTU.BSMUFHRKYRKUWFHMUSBJSTJFHDRTXLFHGUOUWHUOSGYHOIRKJSPFMRU,SBKGXXFKURTXEWHUOSGIHMFTSUMFPFHD.RURKUWFTSLDFKFJMFUSBDHGXWRTXHUOSGMKFDB,JHDYDOOFUUWSMSGXWDO,HTIRKUWGKWGYSGMRUKFDB,--UWFKYRDFSBQWRDSKSQWO.HDDXFTGRTFWGYSGMRKUKYHORTUWRKKFTKFLFJHDDFIUFH-QWRDSKSQWFMK,--UWHJAFMHO,BSMRTKUHTJF,HTISBJSGMKF,KWHAFKQFHMF.UWFQSFUKSBUWFIFJHIFTJF(EWFTEHKTSUUWFESMDIRTIFJHIFTJF?),RTUWFRMQMSUFKUKHXHRTKUYHUFMRHDRKY,WHPF,USHJFMUHRTFCUFTU,HDKSSQFTFIUWFEHOUSUFHRKY.QFMWHQKTSEHIHOKRURKSGMIFYGMFJSTUFYQDHURSTSBUWFRYQFMBFJUUWHUUWFEFKUHTIUWFFHKUJHTYFFURTYGUGHDJSTKSDHURST.UWFUHSRKUKMFDHUFUWHUHUUWFXMFHULFXRTTRTXSBUWFTS-LFXRTTRTX,KQRMRUHTIYHUUFMYFURTYSMUHDJSYLHU.HUDHKUUWFOFDDSEFYQFMSM,UWFKGTSBWFHPFT,UMRGYQWFISPFMKWGWOGTX,UWFIFYSTSBIHMATFKKHTIFHMUW.UWFURUHT,RTWRKIFHUWHXSTO,KUMGJAWRKWFHIHXHRTKUUWFKSDHMPHGDUHTIKWRPFMFIUWFLDGFISYFSBVHIFRTUSBMHXYFTUK.UWFKUHMKDSKUUWFRMTFKUK,UWFYSSTEHTIFMFIHRYDFKKDOHYSTXUWFERDIJWHKYKSBUWFTRXWU.RTIFKQHRMUWFOFDDSEFYQFMSMKSGXWUBHMHTIERIFBSMUWFMFQHRMFMSBUWFWFHPFTK.WFWHITSUUSKFHMJWRTPHRT.SGUSBUWFFHKUFMTKFHMSKFHZGFFT,UWFIRPRTFTRGAH,WSMT-JMSETFIHTIIMHXST-UHRDFI,MFKQDFTIFTURTWFMHMYSMSBBRMF.KWFEFDIFIUWFBRPF-JSDSGMFIMHRTLSERTWFMYHXRJJHGDIMSTHTIMFLGRDUUWFJWRTFKFKAO.LGURURKUSDIUWHUTRGAHBSMXSUUSBRDDUESURTOJMFPRJFKRTUWFLDGFBRMYHYFTU.UWGKLFXHTUWFIGHDRKYSBDSPF--UESKSGDKMSDDRTXUWMSGXWKQHJFHTITFPFMHUMFKUGTURDUWFOVSRTUSXFUWFMUSJSYQDFUFUWFGTRPFMKF.FPFMOSTFWHKUSLGRDIHTFEWRKKAOSBWSQFHTIQFHJF.UWFWFHPFTSBYSIFMTWGYHTRUORKRTIFFIKWHUUFMFIRTUWFJOJDSQFHTKUMGXXDFBSMEFHDUWHTIQSEFM.UWFESMDIRKXMSQRTXRTUWFKWHISESBFXSURKYHTIPGDXHMRUO.ATSEDFIXFRKLSGXWUUWMSGXWHLHIJSTKJRFTJF,LFTFPSDFTJFQMHJURJFIBSMUWFKHAFSBGURDRUO.UWFFHKUHTIUWFEFKU,DRAFUESIMHXSTKUSKKFIRTHKFHSBBFMYFTU,RTPHRTKUMRPFUSMFXHRTUWFVFEFDSBDRBF.EFTFFIHTRGAHHXHRTUSMFQHRMUWFXMHTIIFPHKUHURST;EFHEHRUUWFXMFHUHPHUHM.YFHTEWRDF,DFUGKWHPFHKRQSBUFH.UWFHBUFMTSSTXDSERKLMRXWUFTRTXUWFLHYLSSK,UWFBSGTUHRTKHMFLGLLDRTXERUWIFDRXWU,UWFKSGXWRTXSBUWFQRTFKRKWFHMIRTSGMAFUUDF.DFUGKIMFHYSBFPHTFKJFTJF,HTIDRTXFMRTUWFLFHGURBGDBSSDRKWTFKKSBUWRTXK.";
//        	String decripted = "teabeganasamedicineandgrewintoabeverageinchinaintheeighthcenturyitenteredtherealmofpoetryasoneofthepoliteamusementsthefifteenthcenturysawjapanennobleitintoareligionofaestheticismteaismteaismisacultfoundedontheadorationofthebeautifulamongthesordidfactsofeverydayexistenceitinculcatespurityandharmonythemysteryofmutualcharitytheromanticismofthesocialorderitisessentiallyaworshipoftheimperfectasitisatenderattempttoaccomplishsomethingpossibleinthisimpossiblethingweknowaslifethephilosophyofteaisnotmereaestheticismintheordinaryacceptanceofthetermforitexpressesconjointlywithethicsandreligionourwholepointofviewaboutmanandnatureitishygieneforitenforcescleanlinessitiseconomicsforitshowscomfortinsimplicityratherthaninthecomplexandcostlyitismoralgeometryinasmuchasitdefinesoursenseofproportiontotheuniverseitrepresentsthetruespiritofeasterndemocracybymakingallitsvotariesaristocratsintastethelongisolationofjapanfromtherestoftheworldsoconducivetointrospectionhasbeenhighlyfavourabletothedevelopmentofteaismourhomeandhabitscostumeandcuisineporcelainlacquerpaintingourveryliteratureallhavebeensubjecttoitsinfluencenostudentofjapaneseculturecouldeverignoreitspresenceithaspermeatedtheeleganceofnobleboudoirsandenteredtheabodeofthehumbleourpeasantshavelearnedtoarrangeflowersourmeanestlabourertoofferhissalutationtotherocksandwatersinourcommonparlancewespeakofthemanwithnoteainhimwhenheisinsusceptibletotheseriocomicinterestsofthepersonaldramaagainwestigmatisetheuntamedaesthetewhoregardlessofthemundanetragedyrunsriotinthespringtideofemancipatedemotionsasonewithtoomuchteainhimtheoutsidermayindeedwonderatthisseemingmuchadoaboutnothingwhatatempestinateacuphewillsaybutwhenweconsiderhowsmallafterallthecupofhumanenjoymentishowsoonoverflowedwithtearshoweasilydrainedtothedregsinourquenchlessthirstforinfinityweshallnotblameourselvesformakingsomuchoftheteacup";
//            System.out.printf("word count->%d<-\n", aSubstitutionCipher.wordCount(decripted));

//        	String cText = "ufhlfxhthkhyfirjrtfhtixmfertushlfpfmhxfrtjwrthrtuwffrxwuwjftugmoruftufmfiuwfmfhdysbqsfumohkstfsbuwfqsdrufhygkfyftukuwfbrbufftuwjftugmokhevhqhtfttsldfrurtushmfdrxrstsbhfkuwfurjrkyufhrkyufhrkyrkhjgdubsgtifistuwfhismhurstsbuwflfhgurbgdhystxuwfksmiribhjuksbfpfmoihofcrkuftjfrurtjgdjhufkqgmruohtiwhmystouwfyokufmosbygughdjwhmruouwfmsyhturjrkysbuwfksjrhdsmifmrurkfkkfturhddohesmkwrqsbuwfryqfmbfjuhkrurkhuftifmhuufyquushjjsyqdrkwksyfuwrtxqskkrldfrtuwrkryqskkrldfuwrtxefatsehkdrbfuwfqwrdsksqwosbufhrktsuyfmfhfkuwfurjrkyrtuwfsmirthmohjjfquhtjfsbuwfufmybsmrufcqmfkkfkjstvsrtudoeruwfuwrjkhtimfdrxrstsgmewsdfqsrtusbprfehlsguyhthtithugmfrurkwoxrftfbsmruftbsmjfkjdfhtdrtfkkrurkfjstsyrjkbsmrukwsekjsybsmurtkryqdrjruomhuwfmuwhtrtuwfjsyqdfchtijskudorurkysmhdxfsyfumorthkygjwhkruifbrtfksgmkftkfsbqmsqsmurstusuwfgtrpfmkfrumfqmfkftukuwfumgfkqrmrusbfhkufmtifysjmhjoloyhartxhddrukpsuhmrfkhmrkusjmhukrtuhkufuwfdstxrksdhurstsbvhqhtbmsyuwfmfkusbuwfesmdiksjstigjrpfusrtumskqfjurstwhklfftwrxwdobhpsgmhldfusuwfifpfdsqyftusbufhrkysgmwsyfhtiwhlrukjskugyfhtijgrkrtfqsmjfdhrtdhjzgfmqhrturtxsgmpfmodrufmhugmfhddwhpflfftkglvfjuusrukrtbdgftjftskugiftusbvhqhtfkfjgdugmfjsgdifpfmrxtsmfrukqmfkftjfruwhkqfmyfhufiuwffdfxhtjfsbtsldflsgisrmkhtiftufmfiuwfhlsifsbuwfwgyldfsgmqfhkhtukwhpfdfhmtfiushmmhtxfbdsefmksgmyfhtfkudhlsgmfmussbbfmwrkkhdguhurstusuwfmsjakhtiehufmkrtsgmjsyystqhmdhtjfefkqfhasbuwfyhteruwtsufhrtwryewftwfrkrtkgkjfqurldfusuwfkfmrsjsyrjrtufmfkuksbuwfqfmksthdimhyhhxhrtefkurxyhurkfuwfgtuhyfihfkuwfufewsmfxhmidfkksbuwfygtihtfumhxfiomgtkmrsurtuwfkqmrtxurifsbfyhtjrqhufifysurstkhkstferuwussygjwufhrtwryuwfsgukrifmyhortiffiestifmhuuwrkkffyrtxygjwhishlsgutsuwrtxewhuhufyqfkurthufhjgqwferddkholguewftefjstkrifmwsekyhddhbufmhdduwfjgqsbwgyhtftvsoyfturkwseksstspfmbdsefieruwufhmkwsefhkrdoimhrtfiusuwfimfxkrtsgmzgftjwdfkkuwrmkubsmrtbrtruoefkwhddtsuldhyfsgmkfdpfkbsmyhartxksygjwsbuwfufhjgq";
//        	aSubstitutionCipher.decipherSubstitutionCipher(cText.toLowerCase());

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
