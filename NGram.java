package decipher;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.HashMap;
import java.util.Map;


/**
 * <p>
 * Reads in a Ngram text file (bigrams.txt, trigram.txt, or quadgram.txt) and uses 
 * the information to score different deciphered text.
 * Code adaped from practialcryptography.com
 * </p>
 * Example first few lines of the quadgram.txt file: 
 * <pre>
 * TION 13168375
 * NTHE 11234972
 * THER 10218035
 * THAT 8980536
 * OFTH 8132597
 * </pre>
 * See <a href="http://practicalcryptography.com/cryptanalysis/text-characterisation/quadgrams/">PracticalCryptograph.com link</a>
 */
public class NGram {

	/** A map the grams (keys) to the score.*/
    private Map<String,Double> gramMap = new HashMap<>();
    /** length of the grams (either 1, 2, 3, or 4) */
    private int length = 0;
    /** All the scores from the file added.  Used for scoring. */
    private long total = 0;
    
    /** 
     * The grams file does hold the lowest occurrence permutations.
     * This floor value is calculated to use when a permutation is missing. 
     */
    double floor = 0;

    /**
     * Reads in the file storing each line into the gramMap to use in the score method.
     * @param fileName the name of the file to use.
     * @throws Exception
     */
    public NGram(String fileName) throws Exception {
    	// first check if this file exists
        File nGramFile = new File(fileName);
        if(!nGramFile.exists()) {
        	// if the file does not exist, print out a detailed error 
        	// of exactly the file the program is looking for.
            String errStr = String.format("File does not exist! %s\n",
            		nGramFile.getAbsolutePath());
            System.out.println(errStr);
            throw new Exception(errStr);
        }
        // first, read all the grams into the gramMap from the file and add each to the total
        try (BufferedReader br = new BufferedReader(new FileReader(nGramFile))) {
            String aLine;
            String[] split = {"",""};
            int value;
            while((aLine = br.readLine()) != null) {
            	// line has gram then a space and value example: TION 13168375
                split = aLine.split(" ");
                value = Integer.parseInt(split[1]);
                total += value;

                gramMap.put(split[0].toLowerCase(), (double)value);
            }
            // Just use the last one to get the length (or N) of this grams file
            length = split[0].length();
        }
        //System.out.printf("total is %d\n", total);
        // calculate the least value to use when the gram is missing from the file
        floor = Math.log10(0.01/(double)total);
        double aValue;
        // now replace the values with the log of the percentage of the total
        for (String aGram: gramMap.keySet()) {
            aValue = gramMap.get(aGram);
            gramMap.put(aGram, Math.log10(aValue/((double)total)));
        }
    }

    /**
     * This returns scoring on all the N grams in the plan text given.
     * The higher the value returned the better
     * @param tryPlantext a String of hopefully good plan text to score 
     * @return 
     */
    double score(String tryPlantext) {
        double score = 0;
        Double lookupVal;
        int end = tryPlantext.length() - length - 1;
        for (int i = 0; i < end; i++) {
           lookupVal = gramMap.get(tryPlantext.substring(i, i+length));
           if(lookupVal != null) {
               score += lookupVal;
           }else{
               score += floor;
           }
        }
        return score;
    }

    /**
     * This is just used to test this class with the quadgrams.txt file.
     * @param args these values are not used.
     */
    public static void main(String[] args) {
        try {
            NGram aQuadGram = new NGram("quadgrams.txt");
            //NGram aQuadGram = new NGram("bigrams.txt");
            String aQuad = "asdf";
            System.out.printf("%s = %f\n", aQuad, aQuadGram.score(aQuad));
            aQuad = "tion";
            System.out.printf("%s = %f\n", aQuad, aQuadGram.score(aQuad));
            aQuad = "helloworld";
            System.out.printf("%s = %f\n", aQuad, aQuadGram.score(aQuad));
            aQuad = "then";
            System.out.printf("%s = %f\n", aQuad, aQuadGram.score(aQuad));
            aQuad = "qkpc";
            System.out.printf("%s = %f\n", aQuad, aQuadGram.score(aQuad));
            aQuad = "atta";
            System.out.printf("%s = %f\n", aQuad, aQuadGram.score(aQuad));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
