import { DateComparisonOperator } from "../../../../types/common";
/**
 * @oas [get] /regions
 * operationId: "GetRegions"
 * summary: "List Regions"
 * description: "Retrieves a list of Regions."
 * x-authenticated: true
 * parameters:
 *  - in: query
 *    name: limit
 *    schema:
 *      type: integer
 *      default: 50
 *    required: false
 *    description: limit the number of regions in response
 *  - in: query
 *    name: offset
 *    schema:
 *      type: integer
 *      default: 0
 *    required: false
 *    description: Offset of regions in response (used for pagination)
 *  - in: query
 *    name: created_at
 *    schema:
 *      type: object
 *    required: false
 *    description: Date comparison for when resulting region was created, i.e. less than, greater than etc.
 *  - in: query
 *    name: updated_at
 *    schema:
 *      type: object
 *    required: false
 *    description: Date comparison for when resulting region was updated, i.e. less than, greater than etc.
 *  - in: query
 *    name: deleted_at
 *    schema:
 *      type: object
 *    required: false
 *    description: Date comparison for when resulting region was deleted, i.e. less than, greater than etc.
 * x-codeSamples:
 *   - lang: JavaScript
 *     label: JS Client
 *     source: |
 *       import Medusa from "@medusajs/medusa-js"
 *       const medusa = new Medusa({ baseUrl: MEDUSA_BACKEND_URL, maxRetries: 3 })
 *       // must be previously logged in or use api token
 *       medusa.admin.regions.list()
 *       .then(({ regions, limit, offset, count }) => {
 *         console.log(regions.length);
 *       });
 *   - lang: Shell
 *     label: cURL
 *     source: |
 *       curl --location --request GET 'https://medusa-url.com/admin/regions' \
 *       --header 'Authorization: Bearer {api_token}'
 * security:
 *   - api_token: []
 *   - cookie_auth: []
 * tags:
 *   - Region
 * responses:
 *   200:
 *     description: OK
 *     content:
 *       application/json:
 *         schema:
 *           properties:
 *             regions:
 *               type: array
 *               items:
 *                 $ref: "#/components/schemas/region"
 *             count:
 *               type: integer
 *               description: The total number of items available
 *             offset:
 *               type: integer
 *               description: The number of items skipped before these items
 *             limit:
 *               type: integer
 *               description: The number of items per page
 *   "400":
 *     $ref: "#/components/responses/400_error"
 *   "401":
 *     $ref: "#/components/responses/unauthorized"
 *   "404":
 *     $ref: "#/components/responses/not_found_error"
 *   "409":
 *     $ref: "#/components/responses/invalid_state_error"
 *   "422":
 *     $ref: "#/components/responses/invalid_request_error"
 *   "500":
 *     $ref: "#/components/responses/500_error"
 */
declare const _default: (req: any, res: any) => Promise<void>;
export default _default;
export declare class AdminGetRegionsPaginationParams {
    limit?: number;
    offset?: number;
}
export declare class AdminGetRegionsParams extends AdminGetRegionsPaginationParams {
    created_at?: DateComparisonOperator;
    updated_at?: DateComparisonOperator;
    deleted_at?: DateComparisonOperator;
}
