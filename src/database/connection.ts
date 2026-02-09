import Knex, { Knex as KnexType } from 'knex';
import { Model } from 'objection';
import knexConfig from './knexfile';
import { config } from '../config';

const environment = config.server.nodeEnv;
const connectionConfig = knexConfig[environment] || knexConfig.development;

const knex: KnexType = Knex(connectionConfig);

Model.knex(knex);

export default knex;
