import { loadAdapter } from '../Adapters/AdapterLoader';
import { WSAdapter } from '../Adapters/WebSocketServer/WSAdapter';
import logger from '../logger';
import events from 'events';
import { inspect } from 'util';

export class ParseWebSocketServer {
  server: Object;

  constructor(server: any, onConnect: Function, config) {
    config.server = server;
    const wss = loadAdapter(config.wssAdapter, WSAdapter, config);
    wss.onListen = () => {
      logger.info('Parse LiveQuery Server started running');
    };
    wss.onConnection = ws => {
      ws.waitingForPong = false;
      const parseWebSocket = new ParseWebSocket(ws);
      ws.on('pong', () => {
        ws.waitingForPong = false;
      });
      ws.on('error', error => {
        logger.error(error.message);
        logger.error(inspect(ws, false));
        void parseWebSocket.disconnectAndTerminate('socket_error');
      });
      onConnect(parseWebSocket);
      // Send ping to client periodically
      const pingIntervalId = setInterval(async () => {
        if (!ws.waitingForPong) {
          ws.ping();
          ws.waitingForPong = true;
        } else {
          clearInterval(pingIntervalId);
          await parseWebSocket.disconnectAndTerminate('pong_timeout');
        }
      }, config.websocketTimeout || 10 * 1000);
      parseWebSocket.on('disconnecting', () => clearInterval(pingIntervalId));
    };
    wss.onError = error => {
      logger.error(error);
    };
    wss.start();
    this.server = wss;
  }

  close() {
    if (this.server && this.server.close) {
      this.server.close();
    }
  }
}

export class ParseWebSocket extends events.EventEmitter {
  ws: any;
  disconnectHandler: Function;
  disconnectPromise: Promise<void>;
  terminated: boolean;

  constructor(ws: any) {
    super();
    ws.onmessage = request =>
      this.emit('message', request && request.data ? request.data : request);
    ws.onclose = () => {
      void this.disconnect('socket_close');
    };
    this.ws = ws;
  }

  setDisconnectHandler(disconnectHandler: Function): void {
    this.disconnectHandler = disconnectHandler;
  }

  disconnect(reason: string): Promise<void> {
    if (this.disconnectPromise) {
      return this.disconnectPromise;
    }
    this.emit('disconnecting', reason);
    this.disconnectPromise = Promise.resolve()
      .then(() => this.disconnectHandler?.(reason))
      .catch(error => logger.error('Failed running LiveQuery socket cleanup', error));
    return this.disconnectPromise;
  }

  async disconnectAndTerminate(reason: string): Promise<void> {
    try {
      await this.disconnect(reason);
    } finally {
      this.terminate();
    }
  }

  terminate(): void {
    if (this.terminated) {
      return;
    }
    this.terminated = true;
    this.ws.terminate();
  }

  send(message: any): void {
    this.ws.send(message);
  }
}
