-- The "Dossier" Query: Trace a single record across all tables
WITH latest_completed_verif AS (
    SELECT APP_SEQ_ID, CREATED_DT
    FROM (
        SELECT
            avp_inner.APP_SEQ_ID,
            avp_inner.CREATED_DT,
            ROW_NUMBER() OVER (PARTITION BY avp_inner.APP_SEQ_ID ORDER BY avp_inner.CREATED_DT DESC) as rn
        FROM APP_VERIF_PROCESS_TX avp_inner
        WHERE avp_inner.STS_CODE = 'ST08' AND avp_inner.ACTION = 'FINAL' AND avp_inner.VERIF_TYPE_CODE = 'TTLV'
    )
    WHERE rn = 1
)
SELECT
    av.APP_SEQ_ID,
    av.APP_VERIF_ID,
    av.STS_CODE as main_status,
    av.ASSIGN_DT as assignment_date,
    lcv.CREATED_DT as completion_date, -- This comes from the history table
    TRUNC(
        CASE
            WHEN 'COMPLETED' = 'COMPLETED' THEN lcv.CREATED_DT -- Checking the 'COMPLETED' path
            ELSE SYSDATE
        END
    ) - TRUNC(av.ASSIGN_DT) AS days_diff_if_completed,
    TRUNC(
        CASE
            WHEN 'PENDING' = 'COMPLETED' THEN lcv.CREATED_DT -- Checking the 'PENDING' path
            ELSE SYSDATE
        END
    ) - TRUNC(av.ASSIGN_DT) AS days_diff_if_pending,
    bm.CTR_CODE
FROM APP_VERIF_TX av
INNER JOIN APP_TX at ON av.APP_SEQ_ID = at.APP_SEQ_ID
INNER JOIN BRANCH_MS bm ON at.BRN_CODE = bm.BRN_CODE
LEFT JOIN latest_completed_verif lcv ON av.APP_SEQ_ID = lcv.APP_SEQ_ID
WHERE av.APP_SEQ_ID = [Your_Problem_App_Seq_Id];

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
