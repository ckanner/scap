#!/usr/bin/env node
import { controllerMain } from '../src/controller_process.js';

process.exitCode = await controllerMain();
