WITH latest_completed_verif AS (
    SELECT APP_VERIF_ID, CREATED_DT
    FROM (
        SELECT
            avp.APP_VERIF_ID,
            avp.CREATED_DT,
            ROW_NUMBER() OVER (
                PARTITION BY avp.APP_VERIF_ID
                ORDER BY avp.CREATED_DT DESC
            ) rn
        FROM APP_VERIF_PROCESS_TX avp
        WHERE avp.STS_CODE = 'ST08'
          AND avp.ACTION = 'FINAL'
          AND avp.VERIF_TYPE_CODE = :verifTypeCode
    )
    WHERE rn = 1
),
data_with_age AS (
    SELECT
        CASE 
            WHEN :statusType = 'COMPLETED'
                THEN TRUNC(lcv.CREATED_DT) - TRUNC(av.ASSIGN_DT)
            ELSE TRUNC(SYSDATE) - TRUNC(av.ASSIGN_DT)
        END AS days_diff
    FROM APP_VERIF_TX av
    JOIN APP_TX at ON av.APP_SEQ_ID = at.APP_SEQ_ID
    JOIN BRANCH_MS bm ON at.BRN_CODE = bm.BRN_CODE
    LEFT JOIN latest_completed_verif lcv ON av.APP_VERIF_ID = lcv.APP_VERIF_ID
    WHERE bm.CIR_CODE = :cirCode
      AND av.VERIF_TYPE_CODE = :verifTypeCode
      AND av.ASSIGN_DT BETWEEN :fromDate AND :toDate
      AND (
          (:statusType = 'PENDING' 
              AND av.STS_CODE IN ('ST02', 'ST06', 'ST14'))
          OR
          (:statusType = 'COMPLETED'
              AND av.STS_CODE = 'ST08'
              AND lcv.CREATED_DT IS NOT NULL)
      )
)
SELECT
    NVL(SUM(CASE WHEN days_diff <= 10 THEN 1 ELSE 0 END), 0) AS lessThan10Days,
    NVL(SUM(CASE WHEN days_diff BETWEEN 11 AND 20 THEN 1 ELSE 0 END), 0) AS between11To20Days,
    NVL(SUM(CASE WHEN days_diff BETWEEN 21 AND 30 THEN 1 ELSE 0 END), 0) AS between21To30Days,
    NVL(SUM(CASE WHEN days_diff > 30 THEN 1 ELSE 0 END), 0) AS moreThan30Days,
    COUNT(*) AS totalCount
FROM data_with_age;
/////

    @Query(value =
        // Step 1: Create a precise lookup for the single, latest, official completion date.
        "WITH latest_completed_verif AS ( " +
        "    SELECT APP_SEQ_ID, CREATED_DT " +
        "    FROM ( " +
        "        SELECT " +
        "            avp_inner.APP_SEQ_ID, " +
        "            avp_inner.CREATED_DT, " +
        "            ROW_NUMBER() OVER (PARTITION BY avp_inner.APP_SEQ_ID ORDER BY avp_inner.CREATED_DT DESC) as rn " +
        "        FROM APP_VERIF_PROCESS_TX avp_inner " +
        "        WHERE avp_inner.STS_CODE = 'ST08' " +
        "          AND avp_inner.ASSIGN_TYPE = 'FINAL' " +
        "          AND avp_inner.VERIF_TYPE_CODE = 'TTLV' " +
        "    ) " +
        "    WHERE rn = 1 " +
        "), " +
        // Step 2: Join data and calculate the age ('days_diff') of each task just ONCE.
        "data_with_age AS ( " +
        "    SELECT " +
        "        TRUNC( " +
        "            CASE " +
        "                WHEN :statusType = 'COMPLETED' THEN lcv.created_dt " +
        "                ELSE SYSDATE " +
        "            END " +
        "        ) - TRUNC(av.ASSIGN_DT) AS days_diff " +
        "    FROM APP_VERIF_TX av " +
        "    INNER JOIN APP_TX at ON av.APP_SEQ_ID = at.APP_SEQ_ID " +
        "    INNER JOIN BRANCH_MS bm ON at.BRN_CODE = bm.BRN_CODE " +
        "    LEFT JOIN latest_completed_verif lcv ON av.APP_SEQ_ID = lcv.APP_SEQ_ID " +
        "    WHERE bm.CTR_CODE = :cirCode " +
        "        AND av.VERIF_TYPE_CODE = :verifTypeCode " +
        "        AND av.ASSIGN_DT BETWEEN :fromDate AND :toDate " +
        "        AND ( " +
        "            (:statusType = 'PENDING' AND av.STS_CODE IN ('ST05', 'ST14')) " +
        "            OR " +
        "            (:statusType = 'COMPLETED' AND av.STS_CODE = 'ST08' AND lcv.created_dt IS NOT NULL) " +
        "        ) " +
        ") " +
        // Step 3: Perform the final aggregation on the prepared data.
        "SELECT " +
        "    SUM(CASE WHEN days_diff <= 10 THEN 1 ELSE 0 END) as less_than_10_days, " +
        "    SUM(CASE WHEN days_diff BETWEEN 11 AND 30 THEN 1 ELSE 0 END) as between_11_30_days, " +
        "    SUM(CASE WHEN days_diff > 30 THEN 1 ELSE 0 END) as more_than_30_days, " +
        "    COUNT(*) as total_count " +
        "FROM data_with_age",
        nativeQuery = true)
    VendorPerformanceReportDto getVendorPerformanceReport(
        @Param("cirCode") String cirCode,
        @Param("verifTypeCode") String verifTypeCode,
        @Param("fromDate") Date fromDate,
        @Param("toDate") Date toDate,
        @Param("statusType") String statusType);

//////////////////////////////////

package com.yourproject.dto;

// This interface defines the structure of the report data.
public interface VendorPerformanceReportDto {

    long getLessThan10Days();

    long getBetween11_30Days(); // Note the alias from the query

    long getMoreThan30Days();

    long getTotalCount();
}
