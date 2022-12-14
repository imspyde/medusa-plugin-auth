import { MigrationInterface, QueryRunner } from "typeorm";
export declare const featureFlag: string;
export declare class lineItemOriginalItemRelation1663059812400 implements MigrationInterface {
    name: string;
    up(queryRunner: QueryRunner): Promise<void>;
    down(queryRunner: QueryRunner): Promise<void>;
}
