/**
 * @oas [post] /products/search
 * operationId: PostProductsSearch
 * summary: Search Products
 * description: "Run a search query on products using the search engine installed on Medusa"
 * parameters:
 *   - (query) q=* {string} The query to run the search with.
 *   - (query) offset {integer} How many products to skip in the result.
 *   - (query) limit {integer} Limit the number of products returned.
 *   - (query) filter {} Filter based on the search engine.
 * x-codeSamples:
 *   - lang: JavaScript
 *     label: JS Client
 *     source: |
 *       import Medusa from "@medusajs/medusa-js"
 *       const medusa = new Medusa({ baseUrl: MEDUSA_BACKEND_URL, maxRetries: 3 })
 *       medusa.products.search({
 *         q: 'Shirt'
 *       })
 *       .then(({ hits }) => {
 *         console.log(hits.length);
 *       });
 *   - lang: Shell
 *     label: cURL
 *     source: |
 *       curl --location --request POST 'https://medusa-url.com/store/products/search?q=Shirt'
 * tags:
 *   - Product
 * responses:
 *   200:
 *     description: OK
 *     content:
 *       application/json:
 *         schema:
 *           properties:
 *             hits:
 *               type: array
 *               description: Array of results. The format of the items depends on the search engine installed on the server.
 *   "400":
 *     $ref: "#/components/responses/400_error"
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
export declare class StorePostSearchReq {
    q?: string;
    offset?: number;
    limit?: number;
    filter?: unknown;
}
