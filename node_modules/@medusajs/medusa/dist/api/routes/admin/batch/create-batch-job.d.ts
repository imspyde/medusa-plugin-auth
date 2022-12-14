import { BatchJob } from "../../../../models";
/**
 * @oas [post] /batch-jobs
 * operationId: "PostBatchJobs"
 * summary: "Create a Batch Job"
 * description: "Creates a Batch Job."
 * x-authenticated: true
 * requestBody:
 *   content:
 *    application/json:
 *      schema:
 *        required:
 *          - type
 *          - context
 *        properties:
 *          type:
 *            type: string
 *            description: The type of batch job to start.
 *            example: product-export
 *          context:
 *            type: object
 *            description: Additional infomration regarding the batch to be used for processing.
 *            example:
 *              shape:
 *                prices:
 *                  - region: null
 *                    currency_code: "eur"
 *                dynamicImageColumnCount: 4
 *                dynamicOptionColumnCount: 2
 *              list_config:
 *                skip: 0
 *                take: 50
 *                order:
 *                  created_at: "DESC"
 *                relations:
 *                  - variants
 *                  - variant.prices
 *                  - images
 *          dry_run:
 *            type: boolean
 *            description: Set a batch job in dry_run mode to get some information on what will be done without applying any modifications.
 *            default: false
 * x-codeSamples:
 *   - lang: JavaScript
 *     label: JS Client
 *     source: |
 *       import Medusa from "@medusajs/medusa-js"
 *       const medusa = new Medusa({ baseUrl: MEDUSA_BACKEND_URL, maxRetries: 3 })
 *       // must be previously logged in or use api token
 *       medusa.admin.batchJobs.create({
 *         type: 'product-export',
 *         context: {},
 *         dry_run: false
 *       }).then((({ batch_job }) => {
 *         console.log(batch_job.id);
 *       });
 *   - lang: Shell
 *     label: cURL
 *     source: |
 *       curl --location --request POST 'https://medusa-url.com/admin/batch-jobs' \
 *       --header 'Content-Type: application/json' \
 *       --header 'Authorization: Bearer {api_token}' \
 *       --data-raw '{
 *           "type": "product-export",
 *           "context": { }
 *       }'
 * security:
 *   - api_token: []
 *   - cookie_auth: []
 * tags:
 *   - Batch Job
 * responses:
 *   201:
 *     description: OK
 *     content:
 *       application/json:
 *         schema:
 *           properties:
 *            batch_job:
 *              $ref: "#/components/schemas/batch_job"
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
export declare class AdminPostBatchesReq {
    type: string;
    context: BatchJob["context"];
    dry_run: boolean;
}
