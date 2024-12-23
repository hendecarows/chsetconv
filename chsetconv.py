#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# pylint: disable=missing-docstring

import argparse
import inspect
import json
import logging
import sys
import traceback
import typing


class Logger:
    logger = None

    @classmethod
    def init(cls, log_name, log_level=logging.INFO):
        cls.logger = logging.getLogger(log_name)
        log_handler = logging.StreamHandler()
        log_handler.setLevel(log_level)
        cls.logger.setLevel(log_level)
        log_handler.setFormatter(
            logging.Formatter(
                '%(asctime)s %(levelname)s: %(message)s'
            )
        )
        cls.logger.addHandler(log_handler)

    @classmethod
    def error(cls, msg, *args, **kwargs):
        cls.logger.error(msg, *args, **kwargs)

    @classmethod
    def warning(cls, msg, *args, **kwargs):
        cls.logger.warning(msg, *args, **kwargs)

    @classmethod
    def info(cls, msg, *args, **kwargs):
        cls.logger.info(msg, *args, **kwargs)

    @classmethod
    def debug(cls, msg, *args, **kwargs):
        cls.logger.debug(msg, *args, **kwargs)

    @classmethod
    def trace_function(cls, msg=''):
        if msg:
            cls.logger.debug(
                '{} {}'.format(
                    inspect.currentframe().f_back.f_code.co_name,
                    msg
                )
            )
        else:
            cls.logger.debug(
                inspect.currentframe().f_back.f_code.co_name,
            )


class Config:

    def __init__(self, desc: str):
        self._encodings = {
            'dvbv5': 'utf-8',
            'dvbv5lnb': 'utf-8',
            'bondvb': 'utf-8',
            'bonpt': 'utf-8',
            'bonptx': 'utf-8',
            'bonpx4': 'cp932',
            'mirakurun': 'utf-8',
        }
        self._newlines = {
            'dvbv5': '\n',
            'dvbv5lnb': '\n',
            'bondvb': '\n',
            'bonpt': '\n',
            'bonptx': '\n',
            'bonpx4': '\r\n',
            'mirakurun': '\n',
        }
        self._input = None
        self._output = None
        self._ignores = set()
        self._args = self.parse_args(desc)
        self._configs = vars(self._args)

    def __enter__(self):
        return self

    def __exit__(self, exception_type, exception_value, traceback):
        if self._input is not None:
            self._input.close()
        if self._output is not None:
            self._output.close()

    def _parse_ignores(self, args):
        self._ignores.add(0)
        self._ignores.add(0xffff)
        if args.ignore:
            for tsid in args.ignore.split(','):
                self._ignores.add(int(tsid, 0))

    def _parse_input_output(self, args):
        args.input = args.input[0]
        if args.input == '-':
            args.input = sys.stdin
        else:
            args.input = open(args.input, mode='r', encoding='utf-8')

        if args.output == '-':
            args.output = sys.stdout
        else:
            args.output = open(
                args.output,
                mode='w',
                encoding=self._encodings[args.format],
                newline=self._newlines[args.format],
            )

    def parse_args(self, desc):
        parser = argparse.ArgumentParser(
            description=desc
        )
        parser.add_argument(
            '--log',
            help='log level. (error,warning,info,debug)',
            default='info',
            choices=['error', 'warning', 'info', 'debug'],
        )
        parser.add_argument(
            '--format',
            help='output format (dvbv5,dvbv5lnb,bondvb,bonpt,bonptx,bonpx4,mirakurun)',
            default='dvbv5',
            choices=['dvbv5', 'dvbv5lnb', 'bondvb', 'bonpt', 'bonptx', 'bonpx4', 'mirakurun'],
        )
        parser.add_argument(
            '--ignore',
            metavar='TSID1,TSID2...',
            help='ignore TSID1,TSID2,...',
            type=str,
            default='',
        )

        parser.add_argument(
            'input',
            help='input filename (stdin)',
            nargs=1,
            type=str,
            default='-',
        )
        parser.add_argument(
            'output',
            help='output filename (stdout)',
            nargs='?',
            type=str,
            default='-',
        )

        # parse
        args = parser.parse_args()

        # description
        args.description = desc

        # log level
        args.log_level = {
            'error': logging.ERROR,
            'warning': logging.WARNING,
            'info': logging.INFO,
            'debug':  logging.DEBUG,
        }[args.log]

        self._parse_ignores(args)
        self._parse_input_output(args)

        return args

    def get(self, option: str):
        return self._configs[option]

    def ignores(self) -> set:
        return self._ignores

    def format(self) -> str:
        return self._args.format

    def input(self) -> str:
        return self._args.input

    def output(self) -> str:
        return self._args.output


class BaseConverter:

    TRANSPONDER_SIZE_BS = 12
    TRANSPONDER_SIZE_CS = 12

    def __init__(self, jsons: json, format: str, ignores: set):
        self._jsons = jsons
        self._format = format
        self._ignores = ignores

    def dump(self):
        pass

    def is_ignore_tsid(self, tsid: int) -> bool:
        return (tsid in self._ignores)

    def bonpx4_comment(self):
        return [
            ';',
            '; BonDriver_PX4 チャンネル定義ファイル (ISDB-S) (日本における衛星波デジタル放送用)',
            '; (BonDriver_PT3-STのChSet.txtと互換性あり)',
            ';',
            '; チャンネル空間定義 ($チャンネル空間名<TAB>チャンネル空間ID)',
            '$BS\t0',
            '$CS110\t1',
            ';',
            '; チャンネル定義 (チャンネル名<TAB>チャンネル空間ID<TAB>チャンネルID<TAB>PTX内部チャンネルID<TAB>TSID(ISDB-S用))'
        ]

    def bonptx_header_bs(self):
        return [
            '[Space.BS]',
            'Name=BS',
            'System=ISDB-S',
            '',
            '[Space.BS.Channel]',
        ]

    def bonptx_header_cs(self):
        return [
            '',
            '[Space.CS110]',
            'Name=CS110',
            'System=ISDB-S',
            '',
            '[Space.CS110.Channel]',
        ]


class ISDBScannerDVBv5Converter(BaseConverter):

    def __init__(self, jsons: json, format: str, ignores: set):
        super().__init__(jsons, format, ignores)

    def dump(self):
        buf = []
        if 'BS' in self._jsons:
            for r in self._jsons['BS']:
                if self.is_ignore_tsid(r['transport_stream_id']):
                    continue
                buf.append('[{}]'.format(r['physical_channel_recpt1']))
                buf.append('\tDELIVERY_SYSTEM = ISDBS')
                buf.append('\tFREQUENCY = {}'.format(int(r['satellite_frequency'] *10**6) - 10678000))
                buf.append('\tSTREAM_ID = {}'.format(r['transport_stream_id']))

        if 'CS' in self._jsons:
            for r in self._jsons['CS']:
                if self.is_ignore_tsid(r['transport_stream_id']):
                    continue
                buf.append('[{}]'.format(r['physical_channel_recpt1']))
                buf.append('\tDELIVERY_SYSTEM = ISDBS')
                buf.append('\tFREQUENCY = {}'.format(int(r['satellite_frequency'] *10**6) - 10678000))
                buf.append('\tSTREAM_ID = {}'.format(r['transport_stream_id']))

        return buf

class ISDBScannerDVBv5LnbConverter(BaseConverter):

    def __init__(self, jsons: json, format: str, ignores: set):
        super().__init__(jsons, format, ignores)

    def dump(self):
        buf = []
        if 'BS' in self._jsons:
            for r in self._jsons['BS']:
                if self.is_ignore_tsid(r['transport_stream_id']):
                    continue
                buf.append('[{}]'.format(r['physical_channel_recpt1']))
                buf.append('\tDELIVERY_SYSTEM = ISDBS')
                buf.append('\tLNB = 110BS')
                buf.append('\tFREQUENCY = {}'.format(int(r['satellite_frequency'] *10**6)))
                buf.append('\tSTREAM_ID = {}'.format(r['transport_stream_id']))

        if 'CS' in self._jsons:
            for r in self._jsons['CS']:
                if self.is_ignore_tsid(r['transport_stream_id']):
                    continue
                buf.append('[{}]'.format(r['physical_channel_recpt1']))
                buf.append('\tDELIVERY_SYSTEM = ISDBS')
                buf.append('\tLNB = 110BS')
                buf.append('\tFREQUENCY = {}'.format(int(r['satellite_frequency'] *10**6)))
                buf.append('\tSTREAM_ID = {}'.format(r['transport_stream_id']))

        return buf

class ISDBScannerBonDVBConverter(BaseConverter):

    def __init__(self, jsons: json, format: str, ignores: set):
        super().__init__(jsons, format, ignores)

    def dump(self):
        buf = []
        bonch = 0
        buf.append('#ISDB_S')
        if 'BS' in self._jsons:
            buf.append('; BS')
            for r in self._jsons['BS']:
                if self.is_ignore_tsid(r['transport_stream_id']):
                    continue
                freqidx = (r['satellite_transponder'] -  1) // 2
                buf.append('{}\t{}\t{}\t0x{:x}'.format(r['physical_channel'], bonch, freqidx, r['transport_stream_id']))
                bonch += 1

        if 'CS' in self._jsons:
            buf.append('')
            buf.append('; CS')
            for r in self._jsons['CS']:
                if self.is_ignore_tsid(r['transport_stream_id']):
                    continue
                freqidx = BaseConverter.TRANSPONDER_SIZE_BS + (r['satellite_transponder'] -  1) // 2
                buf.append('{}\t{}\t{}\t0x{:x}'.format(r['physical_channel'], bonch, freqidx, r['transport_stream_id']))
                bonch += 1

        return buf

class ISDBScannerBonPTConverter(BaseConverter):

    def __init__(self, jsons: json, format: str, ignores: set):
        super().__init__(jsons, format, ignores)

    def dump(self):
        buf = []
        bonch = 0
        buf.append('#ISDB_S')
        if 'BS' in self._jsons:
            buf.append('; BS')
            for r in self._jsons['BS']:
                if self.is_ignore_tsid(r['transport_stream_id']):
                    continue
                freqidx = (r['satellite_transponder'] -  1) // 2
                buf.append('{}\t{}\t{}\t{}'.format(r['physical_channel'], bonch, freqidx, r['satellite_slot_number']))
                bonch += 1

        if 'CS' in self._jsons:
            buf.append('')
            buf.append('; CS')
            for r in self._jsons['CS']:
                if self.is_ignore_tsid(r['transport_stream_id']):
                    continue
                freqidx = BaseConverter.TRANSPONDER_SIZE_BS + (r['satellite_transponder'] -  1) // 2
                buf.append('{}\t{}\t{}\t{}'.format(r['physical_channel'], bonch, freqidx, 0))
                bonch += 1

        return buf


class ISDBScannerBonPTXConverter(BaseConverter):

    def __init__(self, jsons: json, format: str, ignores: set):
        super().__init__(jsons, format, ignores)

    def dump(self):
        buf = []
        if 'BS' in self._jsons:
            bonch = 0
            buf.extend(self.bonptx_header_bs())
            for r in self._jsons['BS']:
                if self.is_ignore_tsid(r['transport_stream_id']):
                    continue
                freqidx = (r['satellite_transponder'] -  1) // 2
                buf.append('Ch{}={},{},{}'.format(bonch, r['physical_channel'], freqidx, r['satellite_slot_number']))
                bonch += 1

        if 'CS' in self._jsons:
            bonch = 0
            buf.extend(self.bonptx_header_cs())
            for r in self._jsons['CS']:
                if self.is_ignore_tsid(r['transport_stream_id']):
                    continue
                freqidx = BaseConverter.TRANSPONDER_SIZE_BS + (r['satellite_transponder'] -  1) // 2
                buf.append('Ch{}={}/TS0,{},{}'.format(bonch, r['physical_channel'], freqidx, 0))
                bonch += 1

        return buf

class ISDBScannerBonPX4Converter(BaseConverter):

    def __init__(self, jsons: json, format: str, ignores: set):
        super().__init__(jsons, format, ignores)

    def dump(self):
        buf = []
        buf.extend(self.bonpx4_comment())
        if 'BS' in self._jsons:
            space = 0
            bonch = 0
            buf.append('; [BS]')
            for r in self._jsons['BS']:
                if self.is_ignore_tsid(r['transport_stream_id']):
                    continue
                freqidx = (r['satellite_transponder'] -  1) // 2
                buf.append('{}\t{}\t{}\t{}\t{}'.format(r['physical_channel'], space, bonch, freqidx, r['transport_stream_id']))
                bonch += 1

        if 'CS' in self._jsons:
            space = 1
            bonch = 0
            buf.append('; [CS]')
            for r in self._jsons['CS']:
                if self.is_ignore_tsid(r['transport_stream_id']):
                    continue
                freqidx = BaseConverter.TRANSPONDER_SIZE_BS + (r['satellite_transponder'] -  1) // 2
                buf.append('{}\t{}\t{}\t{}\t{}'.format(r['physical_channel'], space, bonch, freqidx, r['transport_stream_id']))
                bonch += 1

        return buf

class ISDBScannerMirakurunConverter(BaseConverter):

    def __init__(self, jsons: json, format: str, ignores: set):
        super().__init__(jsons, format, ignores)

    def dump(self):
        buf = []
        if 'BS' in self._jsons:
            for r in self._jsons['BS']:
                if self.is_ignore_tsid(r['transport_stream_id']):
                    continue
                buf.append('- name: {}'.format(r['physical_channel_recpt1']))
                buf.append('  type: BS')
                buf.append('  channel: {}'.format(r['physical_channel_recpt1']))
                buf.append('  isDisabled: false')

        if 'CS' in self._jsons:
            for r in self._jsons['CS']:
                if self.is_ignore_tsid(r['transport_stream_id']):
                    continue
                buf.append('- name: {}'.format(r['physical_channel_recpt1']))
                buf.append('  type: CS')
                buf.append('  channel: {}'.format(r['physical_channel_recpt1']))
                buf.append('  isDisabled: false')

        return buf

class Px4TsIdDVBv5Converter(BaseConverter):

    def __init__(self, jsons: json, format: str, ignores: set):
        super().__init__(jsons, format, ignores)

    def dump(self):
        buf = []
        if 'BS' in self._jsons:
            for r in self._jsons['BS']:
                if r['has_lock'] == False:
                    continue
                for idx, tsid in enumerate(r['transport_stream_id']):
                    if self.is_ignore_tsid(tsid):
                        continue
                    buf.append('[BS{:02d}_{}]'.format(r['number'], idx))
                    buf.append('\tDELIVERY_SYSTEM = ISDBS')
                    buf.append('\tFREQUENCY = {}'.format(r['frequency_if_khz']))
                    buf.append('\tSTREAM_ID = {}'.format(tsid))

        if 'CS' in self._jsons:
            for r in self._jsons['CS']:
                if r['has_lock'] == False:
                    continue
                for idx, tsid in enumerate(r['transport_stream_id']):
                    if self.is_ignore_tsid(tsid):
                        continue
                    buf.append('[CS{}]'.format(r['number']))
                    buf.append('\tDELIVERY_SYSTEM = ISDBS')
                    buf.append('\tFREQUENCY = {}'.format(r['frequency_if_khz']))
                    buf.append('\tSTREAM_ID = {}'.format(tsid))

        return buf

class Px4TsIdDVBv5LnbConverter(BaseConverter):

    def __init__(self, jsons: json, format: str, ignores: set):
        super().__init__(jsons, format, ignores)

    def dump(self):
        buf = []
        if 'BS' in self._jsons:
            for r in self._jsons['BS']:
                if r['has_lock'] == False:
                    continue
                for idx, tsid in enumerate(r['transport_stream_id']):
                    if self.is_ignore_tsid(tsid):
                        continue
                    buf.append('[BS{:02d}_{}]'.format(r['number'], idx))
                    buf.append('\tDELIVERY_SYSTEM = ISDBS')
                    buf.append('\tLNB = 110BS')
                    buf.append('\tFREQUENCY = {}'.format(r['frequency_khz']))
                    buf.append('\tSTREAM_ID = {}'.format(tsid))

        if 'CS' in self._jsons:
            for r in self._jsons['CS']:
                if r['has_lock'] == False:
                    continue
                for idx, tsid in enumerate(r['transport_stream_id']):
                    if self.is_ignore_tsid(tsid):
                        continue
                    buf.append('[CS{}]'.format(r['number']))
                    buf.append('\tDELIVERY_SYSTEM = ISDBS')
                    buf.append('\tLNB = 110BS')
                    buf.append('\tFREQUENCY = {}'.format(r['frequency_khz']))
                    buf.append('\tSTREAM_ID = {}'.format(tsid))

        return buf

class Px4TsIdBonDVBConverter(BaseConverter):

    def __init__(self, jsons: json, format: str, ignores: set):
        super().__init__(jsons, format, ignores)

    def dump(self):
        buf = []
        bonch = 0
        buf.append('#ISDB_S')
        if 'BS' in self._jsons:
            buf.append('; BS')
            for r in self._jsons['BS']:
                if r['has_lock'] == False:
                    continue
                for idx, tsid in enumerate(r['transport_stream_id']):
                    if self.is_ignore_tsid(tsid):
                        continue
                    buf.append(
                        'BS{:02d}/TS{}\t{}\t{}\t0x{:04x}'.format(
                            r['number'], idx, bonch, r['frequency_idx'], tsid
                        )
                    )
                    bonch += 1

        if 'CS' in self._jsons:
            buf.append('')
            buf.append('; CS')
            for r in self._jsons['CS']:
                if r['has_lock'] == False:
                    continue
                for idx, tsid in enumerate(r['transport_stream_id']):
                    if self.is_ignore_tsid(tsid):
                        continue
                    buf.append(
                        'ND{:02d}\t{}\t{}\t0x{:04x}'.format(
                            r['number'], bonch, r['frequency_idx'], tsid
                        )
                    )
                    bonch += 1

        return buf

class Px4TsIdBonPTConverter(BaseConverter):

    def __init__(self, jsons: json, format: str, ignores: set):
        super().__init__(jsons, format, ignores)

    def dump(self):
        buf = []
        bonch = 0
        buf.append('#ISDB_S')
        if 'BS' in self._jsons:
            buf.append('; BS')
            for r in self._jsons['BS']:
                if r['has_lock'] == False:
                    continue
                for idx, tsid in enumerate(r['transport_stream_id']):
                    if self.is_ignore_tsid(tsid):
                        continue
                    buf.append(
                        'BS{:02d}/TS{}\t{}\t{}\t{}'.format(
                            r['number'], idx, bonch, r['frequency_idx'], idx
                        )
                    )
                    bonch += 1

        if 'CS' in self._jsons:
            buf.append('')
            buf.append('; CS')
            for r in self._jsons['CS']:
                if r['has_lock'] == False:
                    continue
                for idx, tsid in enumerate(r['transport_stream_id']):
                    if self.is_ignore_tsid(tsid):
                        continue
                    buf.append(
                        'ND{:02d}\t{}\t{}\t{}'.format(
                            r['number'], bonch, r['frequency_idx'], idx
                        )
                    )
                    bonch += 1

        return buf

class Px4TsIdBonPTXConverter(BaseConverter):

    def __init__(self, jsons: json, format: str, ignores: set):
        super().__init__(jsons, format, ignores)

    def dump(self):
        buf = []
        if 'BS' in self._jsons:
            bonch = 0
            buf.extend(self.bonptx_header_bs())
            for r in self._jsons['BS']:
                if r['has_lock'] == False:
                    continue
                for idx, tsid in enumerate(r['transport_stream_id']):
                    if self.is_ignore_tsid(tsid):
                        continue
                    buf.append(
                        'Ch{}=BS{:02d}/TS{},{},{}'.format(
                            bonch, r['number'], idx, r['frequency_idx'], idx
                        )
                    )
                    bonch += 1

        if 'CS' in self._jsons:
            bonch = 0
            buf.extend(self.bonptx_header_cs())
            for r in self._jsons['CS']:
                if r['has_lock'] == False:
                    continue
                for idx, tsid in enumerate(r['transport_stream_id']):
                    if self.is_ignore_tsid(tsid):
                        continue
                    buf.append(
                        'Ch{}=ND{:02d}/TS{},{},{}'.format(
                            bonch, r['number'], idx, r['frequency_idx'], idx
                        )
                    )
                    bonch += 1

        return buf

class Px4TsIdBonPX4Converter(BaseConverter):

    def __init__(self, jsons: json, format: str, ignores: set):
        super().__init__(jsons, format, ignores)

    def dump(self):
        buf = []
        buf.extend(self.bonpx4_comment())
        if 'BS' in self._jsons:
            bonch = 0
            bonsp = 0
            buf.append('; [BS]')
            for r in self._jsons['BS']:
                if r['has_lock'] == False:
                    continue
                for idx, tsid in enumerate(r['transport_stream_id']):
                    if self.is_ignore_tsid(tsid):
                        continue
                    buf.append(
                        'BS{:02d}/TS{}\t{}\t{}\t{}\t{}'.format(
                            r['number'], idx, bonsp, bonch, r['frequency_idx'], tsid
                        )
                    )
                    bonch += 1

        if 'CS' in self._jsons:
            bonch = 0
            bonsp = 1
            buf.append('; [CS]')
            for r in self._jsons['CS']:
                if r['has_lock'] == False:
                    continue
                tsid = r['transport_stream_id'][0]
                if self.is_ignore_tsid(tsid):
                    continue
                buf.append(
                    'ND{:02d}\t{}\t{}\t{}\t{}'.format(
                        r['number'], bonsp, bonch, r['frequency_idx'], tsid
                    )
                )
                bonch += 1

        return buf

class Px4TsIdMirakurunConverter(BaseConverter):

    def __init__(self, jsons: json, format: str, ignores: set):
        super().__init__(jsons, format, ignores)

    def dump(self):
        buf = []
        if 'BS' in self._jsons:
            for r in self._jsons['BS']:
                if r['has_lock'] == False:
                    continue
                for idx, tsid in enumerate(r['transport_stream_id']):
                    if self.is_ignore_tsid(tsid):
                        continue
                    buf.append('- name: BS{:02d}_{}'.format(r['number'], idx))
                    buf.append('  type: BS')
                    buf.append('  channel: BS{:02d}_{}'.format(r['number'], idx))
                    buf.append('  isDisabled: false')

        if 'CS' in self._jsons:
            for r in self._jsons['CS']:
                if r['has_lock'] == False:
                    continue
                for idx, tsid in enumerate(r['transport_stream_id']):
                    if self.is_ignore_tsid(tsid):
                        continue
                    buf.append('- name: CS{:d}'.format(r['number']))
                    buf.append('  type: CS')
                    buf.append('  channel: CS{:d}'.format(r['number']))
                    buf.append('  isDisabled: false')

        return buf

class Converter:

    def __init__(self, jsons: json, format: str, ignores: set):
        json_type = self.get_json_type(jsons)
        Logger.debug('json = {}'.format(json_type))
        if json_type == 'ISDBScanner':
            self._converter: BaseConverter = {
                'dvbv5': ISDBScannerDVBv5Converter(jsons, format, ignores),
                'dvbv5lnb': ISDBScannerDVBv5LnbConverter(jsons, format, ignores),
                'bondvb': ISDBScannerBonDVBConverter(jsons, format, ignores),
                'bonpt': ISDBScannerBonPTConverter(jsons, format, ignores),
                'bonptx': ISDBScannerBonPTXConverter(jsons, format, ignores),
                'bonpx4': ISDBScannerBonPX4Converter(jsons, format, ignores),
                'mirakurun': ISDBScannerMirakurunConverter(jsons, format, ignores),
            }[format]
        elif json_type == 'px4tsid':
            self._converter: BaseConverter = {
                'dvbv5': Px4TsIdDVBv5Converter(jsons, format, ignores),
                'dvbv5lnb': Px4TsIdDVBv5LnbConverter(jsons, format, ignores),
                'bondvb': Px4TsIdBonDVBConverter(jsons, format, ignores),
                'bonpt': Px4TsIdBonPTConverter(jsons, format, ignores),
                'bonptx': Px4TsIdBonPTXConverter(jsons, format, ignores),
                'bonpx4': Px4TsIdBonPX4Converter(jsons, format, ignores),
                'mirakurun': Px4TsIdMirakurunConverter(jsons, format, ignores),
            }[format]
        else:
            raise Exception('unknown json type')
        Logger.debug('converter = {}'.format(self._converter))

    def dump(self):
        return self._converter.dump()

    def get_json_type(self, jsons: json) -> str:
        if 'BS' in jsons:
            r = jsons['BS']
            if len(r) > 0:
                if 'physical_channel' in r[0]:
                    return 'ISDBScanner'
                elif 'frequency_if_khz' in r[0]:
                    return  'px4tsid'
        elif 'CS' in jsons:
            r = jsons['CS']
            if len(r) > 0:
                if 'physical_channel' in r[0]:
                    return  'ISDBScanner'
                elif 'frequency_if_khz' in r[0]:
                    return 'px4tsid'
        else:
            return ''


def main():

    with Config('convert from json to channel set') as config:
        Logger.init(__name__, config.get('log_level'))
        jsons = json.load(config.input())
        converter = Converter(jsons, config.format(), config.ignores())
        buf = converter.dump()
        for s in buf:
            print(s, file=config.output())


if __name__ == '__main__':
    try:
        main()
    except Exception as err:
        print(traceback.format_exc(), file=sys.stderr)
