# chsetconv

[ISDBScanner][link_isdbscanner]で出力したJSONファイルからBS,CSのトランスポンダに含まれるTSIDを取得し、
[BonDriverProxy_Linux][link_bdpl]や[BonDriver_LinuxPTX][link_bonptx]など、
Linux版BonDriverの設定ファイルに変換するプログラムです。なお、[px4tsid][link_px4tsid]にも対応しています。

## インストール

### Linux

```console
git clone https://github.com/hendecarows/chsetconv.git
cd chsetconv
cp chsetconv.py ~/bin
```

## 使用方法

libdvbv5形式で出力します。

```console
chsetconv.py --format dvbv5 Channels.json dvbv5_channels_isdbs.conf
```

[BonDriver_DVB.conf][link_bdpl]形式で出力します。出力は`#ISDB_S`部分のみです。

```console
chsetconv.py --format bondvb Channels.json bondvb.txt
```

[BonDriver_LinuxPT.conf][link_bdpl]形式で出力します。出力は`#ISDB_S`部分のみです。

```console
chsetconv.py --format bonpt Channels.json bonpt.txt
```

[BonDriver_LinuxPTX.ini][link_bonptx]形式で出力します。

```console
chsetconv.py --format bonptx Channels.json bonptx.txt
```

[BonDriver_PX4-S.ChSet.txt][link_bonpx4]形式で出力します。

```console
chsetconv.py --format bonpx4 Channels.json BonDriver_PX4-S.ChSet.txt
```

移動前のTSID等不必要なTSIDが含まれている場合は、`--ignore`オプションで出力から除外して下さい。

```console
chsetconv.py --format bonpx4 --ignore 16529,18099,18130 Channels.json BonDriver_PX4-S.ChSet.txt
```

[link_isdbscanner]: https://github.com/tsukumijima/ISDBScanner
[link_px4tsid]: https://github.com/hendecarows/px4tsid
[link_bdpl]: https://github.com/u-n-k-n-o-w-n/BonDriverProxy_Linux
[link_bonptx]: https://github.com/hendecarows/BonDriver_LinuxPTX
[link_bonpx4]: https://github.com/tsukumijima/px4_drv
