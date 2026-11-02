from .base import BaseCollector


# yay virusshare does not need an api key
class VirusShareCollector(BaseCollector):
  @property
  def source_name(self):
    return 'virusshare'

  @property
  def fieldnames(self):
    return ['md5']

  def collect(self):
    urls = [f'https://virusshare.com/hashfiles/VirusShare_{i:05}.md5' for i in range(30)]
    res = []
    
    for url in urls:
      response = self.session.get(url)
      response.raise_for_status()
      
      lines = response.text.splitlines()

      for line in lines:
        if line.startswith('#'):
          continue

        res.append(line)

    return res
