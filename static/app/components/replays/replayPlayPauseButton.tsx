import type {ButtonProps} from 'sentry/components/core/button';
import {Button} from 'sentry/components/core/button';
import {useReplayContext} from 'sentry/components/replays/replayContext';
import {IconPause, IconPlay, IconRefresh} from 'sentry/icons';
import {t} from 'sentry/locale';

function ReplayPlayPauseButton(props: Partial<ButtonProps> & {isLoading?: boolean}) {
  const {isFinished, isPlaying, restart, togglePlayPause} = useReplayContext();

  return isFinished ? (
    <Button
      title={t('Restart Replay')}
      icon={<IconRefresh />}
      onClick={restart}
      aria-label={t('Restart Replay')}
      priority="primary"
      {...props}
    />
  ) : (
    <Button
      title={isPlaying ? t('Pause') : t('Play')}
      icon={isPlaying ? <IconPause /> : <IconPlay />}
      onClick={() => togglePlayPause(!isPlaying)}
      aria-label={isPlaying ? t('Pause') : t('Play')}
      priority="primary"
      disabled={props.isLoading}
      {...props}
    />
  );
}

export default ReplayPlayPauseButton;
