""" This is a module which exports a set of plotters based on
matplotlib. Yoy will need to have matplotlib installed using something
like:

apt-get install python-matplotlib

"""
import pyflag.DB as DB
import pyflag.Graph as Graph

try:
    import matplotlib
    matplotlib.use('Agg')
    
    from matplotlib.backends.backend_agg import FigureCanvasAgg as FigureCanvas
    from matplotlib.figure import Figure
    
    import numpy as np

    import matplotlib.image as image
    import matplotlib.figure as figure
    import StringIO
    from matplotlib.backends.backend_agg import FigureCanvasAgg as FigureCanvas
    import tempfile
    import matplotlib.dates as dates
    from matplotlib.ticker import MaxNLocator

except ImportError:
    active = False

class LinePlot(Graph.GenericGraph):
    name = 'Line Plot'

    def form(self, query, result):
        pass

    def plot(self, gen, query, result, figure_args = None, plot_args = None, *args):
        color_list = ['b', 'r', 'm', 'c', 'burlywood']
        if not figure_args:
            figure_args = {}
        if not plot_args:
            plot_args = {}

        timestamp = figure_args.pop("timestamp", False)

        fig = figure.Figure(**figure_args)
        ax = fig.add_subplot(111)
        x=[]
        y=[]
        for a,b in gen:
            x.append(a)
            y.append(b)

        if 'color' not in plot_args:
            plot_args['color'] = 'k' 


        if timestamp: # Special case to allow plotting the x axis as time
            ax.get_xaxis().set_major_formatter(dates.DateFormatter("%d-%m-%Y\n%H:%M:%S"))
            ax.get_xaxis().set_major_locator(MaxNLocator(6))
            #x = [dates.epoch2num(i) for i in x]
            x = dates.epoch2num(x)

        ax.plot(x,y , '.', **plot_args)
        ax.grid()

        for i, arg in enumerate(args):
            i = []
            j = []
            plot_args['zorder'] = i
            if 'color' in plot_args:
                del plot_args['color']
            if len(color_list) > 0:
                plot_args['color'] = color_list.pop(0)
            if 'markersize' in plot_args:
                plot_args['markersize'] *= 1.3
            else:
                plot_args['markersize'] = matplotlib.defaultParams['lines.markersize'][0] * 1.3
            for a,b in arg:
                i.append(a)
                j.append(b)
            if timestamp:
                i = dates.epoch2num(i)
            ax.plot(i,j , '.', **plot_args)

        ## Make a temporary file name:
        fd = tempfile.TemporaryFile()
        canvas=FigureCanvas(fig)
        canvas.print_figure(fd) 
        fd.seek(0)

        if not query.has_key("download"):
            image = Graph.Image(fd.read())
            result.image(image)
        else:
            result.generator.content_type = "image/png"
            result.generator.generator = [ fd.read(), ]
