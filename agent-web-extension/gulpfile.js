var gulp = require('gulp'),
    concat = require('gulp-concat'),
    rename = require('gulp-rename'),
    uglify = require('gulp-uglify'),
    uglifycss = require('gulp-uglifycss');

gulp.task('js', function () {
    gulp.src(['./src/**/*.js'])
        // .pipe(uglify())
        .pipe(gulp.dest('dist'));
});

gulp.task('js-lib', function () {
    return gulp.src([
        './node_modules/agent-desktop-client/dist/**/*.min.js',
    ])
        .pipe(concat('lib.min.js'))
        .pipe(gulp.dest('dist'));
});

gulp.task('css', function () {
    gulp.src(['./src/**/*.css'])
        .pipe(rename('app.min.css'))
        .pipe(uglifycss({
            "maxLineLen": 80,
            "uglyComments": true
        }))
        .pipe(gulp.dest('dist'));
});

gulp.task('html', function () {
    gulp.src(['./src/**/*.png'])
        .pipe(gulp.dest('dist'));

    gulp.src(['./src/**/manifest.json'])
        .pipe(gulp.dest('dist'));

    return gulp.src(['./src/**/*.html'])
        .pipe(gulp.dest('dist'));
});

gulp.task('watch', function () {
    gulp.watch('src/**/*.js', ['js']);
    gulp.watch('src/**/*.css', ['css']);
    gulp.watch('src/**/*.html', ['html']);
});

gulp.task('default', ['js', 'js-lib', 'css', 'html', 'watch'], function () {

});
