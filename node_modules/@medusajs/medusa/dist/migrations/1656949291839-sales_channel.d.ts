import { MigrationInterface, QueryRunner } from "typeorm";
export declare const featureFlag = "sales_channels";
export declare class salesChannel1656949291839 implements MigrationInterface {
    name: string;
    up(queryRunner: QueryRunner): Promise<void>;
    down(queryRunner: QueryRunner): Promise<void>;
}
